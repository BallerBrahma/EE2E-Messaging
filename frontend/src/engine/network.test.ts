// Integration test for engine/network.ts: spins up the *real* Python relay
// server as a subprocess (same "drive the real server" spirit as
// tests/test_integration.py, just cross-process since this side is now
// TypeScript) and drives this TS WebSocket client against it directly.

import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { generateKeyStore } from './crypto/identity'
import { type IncomingMessage, NetworkClient } from './network'

const here = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(here, '../../..')
const pythonBin = path.join(projectRoot, '.venv', 'bin', 'python')
const PORT = 8993
const URI = `ws://localhost:${PORT}`

let serverProcess: ChildProcessWithoutNullStreams

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
    proc.stderr.on('data', onData) // Python's `logging` module defaults to stderr
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
  const dbDir = await mkdtemp(path.join(tmpdir(), 'e2ee-network-test-'))
  serverProcess = spawn(pythonBin, ['main_server.py', '--port', String(PORT), '--db', path.join(dbDir, 'server.sqlite3')], {
    cwd: projectRoot,
  })
  await waitForServerReady(serverProcess)
}, 20000)

afterAll(() => {
  serverProcess?.kill()
})

describe('NetworkClient against a real relay server', () => {
  it('registers, logs in, publishes keys, fetches a bundle, and delivers a message', async () => {
    const alice = new NetworkClient(URI)
    await alice.connect()
    await alice.register('alice_net', 'alice-server-auth-token')
    await alice.login('alice_net', 'alice-server-auth-token')

    const bob = new NetworkClient(URI)
    await bob.connect()
    await bob.register('bob_net', 'bob-server-auth-token')
    await bob.login('bob_net', 'bob-server-auth-token')

    const aliceKeystore = generateKeyStore('alice_net')
    const bobKeystore = generateKeyStore('bob_net')
    await alice.uploadKeys(aliceKeystore)
    await bob.uploadKeys(bobKeystore)

    const bundle = await alice.fetchBundle('bob_net')
    expect(bundle).not.toBeNull()
    expect(bundle?.signedPrekeyId).toBe(bobKeystore.signedPrekey.keyId)

    const received: IncomingMessage[] = []
    bob.onMessage = (msg) => {
      received.push(msg)
    }

    await alice.sendMessage('bob_net', { hello: 'world' })
    await new Promise((resolve) => setTimeout(resolve, 300))

    expect(received).toHaveLength(1)
    expect(received[0].sender).toBe('alice_net')
    expect(received[0].payload).toEqual({ hello: 'world' })

    await alice.close()
    await bob.close()
  }, 15000)

  it('returns null when fetching a bundle for a user with no published keys', async () => {
    const client = new NetworkClient(URI)
    await client.connect()
    await client.register('carol_net', 'carol-server-auth-token')
    await client.login('carol_net', 'carol-server-auth-token')

    const bundle = await client.fetchBundle('nonexistent_user_xyz')
    expect(bundle).toBeNull()

    await client.close()
  }, 15000)
})
