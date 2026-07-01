// End-to-end integration test for engine/sessionManager.ts: two full client
// stacks (storage + network + session manager) talking through the *real*
// Python relay server, mirroring tests/test_integration.py's scenarios but
// from the TypeScript side of the port.

import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { NetworkClient } from './network'
import { type IncomingEvent, SessionManager } from './sessionManager'
import { LocalStorage } from './storage'

const here = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(here, '../../..')
const pythonBin = path.join(projectRoot, '.venv', 'bin', 'python')
const PORT = 8994
const URI = `ws://localhost:${PORT}`

let serverProcess: ChildProcessWithoutNullStreams
let counter = 0
function uniqueUsername(base: string): string {
  counter += 1
  return `${base}_${Date.now()}_${counter}`
}

function waitForServerReady(proc: ChildProcessWithoutNullStreams): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false
    const timeout = setTimeout(() => {
      if (!settled) {
        settled = true
        reject(new Error('relay server did not start in time'))
      }
    }, 10000)
    const onData = (chunk: Buffer) => {
      if (!settled && chunk.toString().includes('relay server listening')) {
        settled = true
        clearTimeout(timeout)
        resolve()
      }
    }
    proc.stdout.on('data', onData)
    proc.stderr.on('data', onData)
    proc.on('exit', (code) => {
      if (!settled) {
        settled = true
        clearTimeout(timeout)
        reject(new Error(`relay server exited early with code ${code}`))
      }
    })
  })
}

beforeAll(async () => {
  const dbDir = await mkdtemp(path.join(tmpdir(), 'e2ee-session-test-'))
  serverProcess = spawn(pythonBin, ['main_server.py', '--port', String(PORT), '--db', path.join(dbDir, 'server.sqlite3')], {
    cwd: projectRoot,
  })
  await waitForServerReady(serverProcess)
}, 20000)

afterAll(() => {
  serverProcess?.kill()
})

async function makeClient(username: string): Promise<{ storage: LocalStorage; network: NetworkClient; manager: SessionManager }> {
  const storage = await LocalStorage.open(username)
  const { keystore } = await storage.createIdentity(username, 'a reasonably strong password')
  const network = new NetworkClient(URI)
  const manager = new SessionManager(keystore, storage, network)
  await network.connect()
  await network.register(username, 'server-auth-token')
  await network.login(username, 'server-auth-token')
  await manager.publishKeys()
  return { storage, network, manager }
}

const enc = (s: string) => new TextEncoder().encode(s)
const dec = (b: Uint8Array) => new TextDecoder().decode(b)

describe('SessionManager end-to-end', () => {
  it('delivers a 1:1 message via X3DH + ratchet, back and forth', async () => {
    const aliceUsername = uniqueUsername('alice')
    const bobUsername = uniqueUsername('bob')
    const alice = await makeClient(aliceUsername)
    const bob = await makeClient(bobUsername)

    const bobEvents: IncomingEvent[] = []
    bob.network.onMessage = async (incoming) => {
      bobEvents.push(await bob.manager.handleIncoming(incoming))
    }
    const aliceEvents: IncomingEvent[] = []
    alice.network.onMessage = async (incoming) => {
      aliceEvents.push(await alice.manager.handleIncoming(incoming))
    }

    const messageId = await alice.manager.sendText(bobUsername, 'hello bob')
    await new Promise((r) => setTimeout(r, 300))

    expect(bobEvents).toHaveLength(1)
    expect(bobEvents[0].kind).toBe('message')
    expect(bobEvents[0].body.content).toBe('hello bob')
    expect(bobEvents[0].messageId).toBe(messageId)

    const history = await bob.manager.history(aliceUsername)
    expect(history.some((m) => m.messageId === messageId)).toBe(true)

    // reply, exercising the ratchet's receiving-then-sending chain
    await bob.manager.sendText(aliceUsername, 'hi alice')
    await new Promise((r) => setTimeout(r, 300))
    expect(aliceEvents.some((e) => e.body.content === 'hi alice')).toBe(true)

    await alice.network.close()
    await bob.network.close()
  }, 15000)

  it('queues a message for offline delivery and delivers it on next login', async () => {
    const aliceUsername = uniqueUsername('alice')
    const bobUsername = uniqueUsername('bob')
    const alice = await makeClient(aliceUsername)
    const bobStorage = await LocalStorage.open(bobUsername)
    const { keystore: bobKeystore } = await bobStorage.createIdentity(bobUsername, 'a reasonably strong password')
    const bobNetwork = new NetworkClient(URI)
    const bobManager = new SessionManager(bobKeystore, bobStorage, bobNetwork)
    await bobNetwork.connect()
    await bobNetwork.register(bobUsername, 'server-auth-token')
    await bobNetwork.login(bobUsername, 'server-auth-token')
    await bobManager.publishKeys()
    await bobNetwork.close() // bob goes offline

    const messageId = await alice.manager.sendText(bobUsername, 'are you there?')

    // bob reconnects later -- must wire onMessage before login (pending
    // messages get pushed in the same burst as the login response).
    const bobEvents: IncomingEvent[] = []
    const bobNetwork2 = new NetworkClient(URI)
    const bobManager2 = new SessionManager(bobKeystore, bobStorage, bobNetwork2)
    bobNetwork2.onMessage = async (incoming) => {
      bobEvents.push(await bobManager2.handleIncoming(incoming))
    }
    await bobNetwork2.connect()
    await bobNetwork2.login(bobUsername, 'server-auth-token')
    await new Promise((r) => setTimeout(r, 300))

    expect(bobEvents.some((e) => e.messageId === messageId && e.body.content === 'are you there?')).toBe(true)

    await alice.network.close()
    await bobNetwork2.close()
  }, 15000)

  it('creates a group, fans out a message, and supports delete-for-everyone', async () => {
    const aliceUsername = uniqueUsername('alice')
    const bobUsername = uniqueUsername('bob')
    const alice = await makeClient(aliceUsername)
    const bob = await makeClient(bobUsername)

    const bobEvents: IncomingEvent[] = []
    bob.network.onMessage = async (incoming) => {
      bobEvents.push(await bob.manager.handleIncoming(incoming))
    }

    const groupId = await alice.manager.createGroup('Test Group', [bobUsername])
    await new Promise((r) => setTimeout(r, 300))
    expect(bobEvents.some((e) => e.kind === 'group_invite')).toBe(true)
    expect(await bob.storage.groupName(groupId)).toBe('Test Group')

    const conversationId = `group:${groupId}`
    const messageId = await alice.manager.sendText(conversationId, 'hello group')
    await new Promise((r) => setTimeout(r, 300))
    expect(bobEvents.some((e) => e.kind === 'message' && e.body.content === 'hello group')).toBe(true)

    await alice.manager.deleteMessage(conversationId, messageId)
    await new Promise((r) => setTimeout(r, 300))
    expect(bobEvents.some((e) => e.kind === 'delete' && e.messageId === messageId)).toBe(true)
    const bobHistory = await bob.manager.history(conversationId)
    expect(bobHistory.some((m) => m.messageId === messageId)).toBe(false)

    await alice.network.close()
    await bob.network.close()
  }, 15000)

  it('sends and receives a profile picture', async () => {
    const aliceUsername = uniqueUsername('alice')
    const bobUsername = uniqueUsername('bob')
    const alice = await makeClient(aliceUsername)
    const bob = await makeClient(bobUsername)

    // wire both sides' onMessage *before* the warm-up exchange -- otherwise
    // neither side ever decrypts the other's message, so each independently
    // runs X3DH as initiator and they end up with two unrelated one-way
    // sessions instead of one shared bidirectional one.
    const aliceEvents: IncomingEvent[] = []
    alice.network.onMessage = async (incoming) => {
      aliceEvents.push(await alice.manager.handleIncoming(incoming))
    }
    bob.network.onMessage = async (incoming) => {
      await bob.manager.handleIncoming(incoming)
    }

    // establish a real bidirectional session first so alice is a "known
    // recipient" for bob's avatar broadcast
    await alice.manager.sendText(bobUsername, 'hi')
    await new Promise((r) => setTimeout(r, 300))
    await bob.manager.sendText(aliceUsername, 'hi back')
    await new Promise((r) => setTimeout(r, 300))

    const imageBytes = enc('fake-png-bytes')
    await bob.manager.setProfilePicture(imageBytes, 'image/png')
    await new Promise((r) => setTimeout(r, 300))

    expect(aliceEvents.some((e) => e.kind === 'avatar_update')).toBe(true)
    const stored = await alice.manager.avatar(bobUsername)
    expect(stored).not.toBeNull()
    expect(dec(stored as Uint8Array)).toBe('fake-png-bytes')

    await alice.network.close()
    await bob.network.close()
  }, 15000)
})
