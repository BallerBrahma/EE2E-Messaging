import { describe, expect, it } from 'vitest'
import { InvalidRecoveryPhrase, LocalStorage, WrongPassword, groupConversationId } from './storage'

// fake-indexeddb keeps databases alive for the life of the test-file worker,
// so each test uses a unique username to avoid cross-test collisions --
// mirrors the isolation tmp_path gives the Python tests (a fresh sqlite file
// per test).
let counter = 0
function uniqueUsername(base: string): string {
  counter += 1
  return `${base}_${Date.now()}_${counter}`
}

async function makeStorage(username: string): Promise<LocalStorage> {
  const storage = await LocalStorage.open(username)
  await storage.createIdentity(username, 'a reasonably strong password')
  return storage
}

describe('pinned conversations', () => {
  it('sorts a pinned conversation before a more recent unpinned one', async () => {
    const username = uniqueUsername('alice')
    const storage = await makeStorage(username)
    await storage.addContact('bob')
    await storage.addContact('carol')

    await storage.addMessage('bob', 'bob', 'received', 'text', 'm1', { content: 'hi' }, Date.now() / 1000 - 100)
    await storage.addMessage('carol', 'carol', 'received', 'text', 'm2', { content: 'hey' }, Date.now() / 1000)

    // carol is more recent, so she'd normally sort first
    let convos = await storage.listConversations()
    expect(convos.map((c) => c.conversationId)).toEqual(['carol', 'bob'])
    expect(convos.every((c) => !c.pinned)).toBe(true)

    await storage.setPinned('bob', true)
    convos = await storage.listConversations()
    expect(convos.map((c) => c.conversationId)).toEqual(['bob', 'carol'])
    expect(convos.find((c) => c.conversationId === 'bob')?.pinned).toBe(true)

    await storage.setPinned('bob', false)
    convos = await storage.listConversations()
    expect(convos.map((c) => c.conversationId)).toEqual(['carol', 'bob'])
  })

  it('applies pinning to group conversations too', async () => {
    const username = uniqueUsername('alice')
    const storage = await makeStorage(username)
    await storage.createGroup('g1', 'Friends', [username, 'bob'])
    const conversationId = groupConversationId('g1')

    expect(await storage.isPinned(conversationId)).toBe(false)
    await storage.setPinned(conversationId, true)
    expect(await storage.isPinned(conversationId)).toBe(true)

    const convos = await storage.listConversations()
    expect(convos.find((c) => c.conversationId === conversationId)?.pinned).toBe(true)
  })
})

describe('password recovery', () => {
  it('unlocks to the same identity via password or recovery phrase', async () => {
    const username = uniqueUsername('alice')
    const created = await LocalStorage.open(username)
    const { keystore, recoveryPhrase } = await created.createIdentity(username, 'a reasonably strong password')
    const token = await created.serverAuthToken()

    const fromPassword = await LocalStorage.open(username)
    const passwordResult = await fromPassword.unlock('a reasonably strong password')
    expect(passwordResult.keystore.username).toBe(keystore.username)
    expect(passwordResult.serverAuthToken).toBe(token)

    const fromRecovery = await LocalStorage.open(username)
    const recoveryResult = await fromRecovery.unlockWithRecovery(recoveryPhrase)
    expect(recoveryResult.keystore.username).toBe(keystore.username)
    expect(recoveryResult.serverAuthToken).toBe(token)
  })

  it('rejects the wrong password', async () => {
    const username = uniqueUsername('alice')
    await makeStorage(username)
    const reopened = await LocalStorage.open(username)
    await expect(reopened.unlock('definitely the wrong password')).rejects.toThrow(WrongPassword)
  })

  it('rejects a malformed recovery phrase before attempting decryption', async () => {
    const username = uniqueUsername('alice')
    await makeStorage(username)
    const reopened = await LocalStorage.open(username)
    await expect(reopened.unlockWithRecovery('this is not a valid bip39 phrase at all')).rejects.toThrow(InvalidRecoveryPhrase)
  })

  it('rejects a valid but foreign recovery phrase', async () => {
    const aliceUsername = uniqueUsername('alice')
    await makeStorage(aliceUsername)

    const bobUsername = uniqueUsername('bob')
    const bobStorage = await LocalStorage.open(bobUsername)
    const { recoveryPhrase: bobPhrase } = await bobStorage.createIdentity(bobUsername, 'another reasonably strong password')

    const reopened = await LocalStorage.open(aliceUsername)
    await expect(reopened.unlockWithRecovery(bobPhrase)).rejects.toThrow(InvalidRecoveryPhrase)
  })

  it('rotatePassword invalidates the old password but not the recovery phrase', async () => {
    const username = uniqueUsername('alice')
    const created = await LocalStorage.open(username)
    const { keystore, recoveryPhrase } = await created.createIdentity(username, 'the old password')
    const token = await created.serverAuthToken()

    const recovered = await LocalStorage.open(username)
    await recovered.unlockWithRecovery(recoveryPhrase)
    await recovered.rotatePassword('a brand new password')

    const oldPasswordAttempt = await LocalStorage.open(username)
    await expect(oldPasswordAttempt.unlock('the old password')).rejects.toThrow(WrongPassword)

    const newPasswordAttempt = await LocalStorage.open(username)
    const newResult = await newPasswordAttempt.unlock('a brand new password')
    expect(newResult.keystore.username).toBe(keystore.username)
    expect(newResult.serverAuthToken).toBe(token)

    const recoveryStillWorks = await LocalStorage.open(username)
    const stillResult = await recoveryStillWorks.unlockWithRecovery(recoveryPhrase)
    expect(stillResult.serverAuthToken).toBe(token)
  })
})
