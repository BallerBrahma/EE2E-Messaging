// Smoke test for engine/webApi.ts against a real relay server -- exercises
// the public PywebviewApi-shaped surface exactly as the UI would call it
// (register -> forgot password -> recover -> re-login), same in-process
// real-server pattern as tests/test_api.py on the Python side.

import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { webApi } from './webApi'

const here = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(here, '../../..')
const pythonBin = path.join(projectRoot, '.venv', 'bin', 'python')
const PORT = 8995
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
  const dbDir = await mkdtemp(path.join(tmpdir(), 'e2ee-webapi-test-'))
  serverProcess = spawn(pythonBin, ['main_server.py', '--port', String(PORT), '--db', path.join(dbDir, 'server.sqlite3')], {
    cwd: projectRoot,
  })
  await waitForServerReady(serverProcess)
}, 20000)

afterAll(() => {
  serverProcess?.kill()
})

describe('webApi', () => {
  it('reports hasLocalIdentity accurately without side effects', async () => {
    const username = uniqueUsername('nobody')
    expect(await webApi.has_local_identity(username)).toBe(false)
  })

  it('register captures a recovery phrase and logs straight in', async () => {
    const username = uniqueUsername('alice')
    const result = await webApi.register(URI, username, 'the original password')
    expect(result.username).toBe(username)
    expect(result.recovery_phrase.split(' ')).toHaveLength(12)
    expect(await webApi.current_username()).toBe(username)
    expect(await webApi.has_local_identity(username)).toBe(true)

    await webApi.close()
  }, 15000)

  it('supports send/receive and biometric methods are safely stubbed', async () => {
    const aliceUsername = uniqueUsername('alice')
    const bobUsername = uniqueUsername('bob')

    await webApi.register(URI, aliceUsername, 'alice password')
    await webApi.close()
    await webApi.register(URI, bobUsername, 'bob password')
    await webApi.close()

    // biometrics are unavailable on the web build -- verify the stubs behave
    expect(await webApi.has_biometric_support()).toBe(false)
    expect(await webApi.get_remembered_username()).toBeNull()

    await webApi.login(URI, aliceUsername, 'alice password')
    await webApi.add_contact(bobUsername)
    const messageId = await webApi.send_text(bobUsername, 'hello from webApi')
    const history = await webApi.get_history(bobUsername)
    expect(history.some((m) => m.message_id === messageId)).toBe(true)
    await webApi.close()
  }, 15000)

  it('recovers a forgotten password via the recovery phrase and preserves history', async () => {
    const username = uniqueUsername('carol')
    const registered = await webApi.register(URI, username, 'the original password')
    await webApi.add_contact('nonexistent-contact')
    await webApi.close()

    // wrong password fails
    await expect(webApi.login(URI, username, 'wrong password')).rejects.toThrow()

    // recovery phrase + new password gets back in
    const recovered = await webApi.recover_account(URI, username, registered.recovery_phrase, 'a brand new password')
    expect(recovered.username).toBe(username)
    const contacts = await webApi.contacts()
    expect(contacts).toContain('nonexistent-contact')
    await webApi.close()

    // new password now works for a normal login too
    await webApi.login(URI, username, 'a brand new password')
    expect(await webApi.current_username()).toBe(username)
    await webApi.close()
  }, 15000)
})
