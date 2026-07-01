import 'fake-indexeddb/auto'

// Node (this test runner) has no global `WebSocket` client until v22 --
// the real deployed environment (a browser) always has it natively, so
// this polyfill exists purely for the Node-based test run.
if (typeof globalThis.WebSocket === 'undefined') {
  const { WebSocket } = await import('ws')
  ;(globalThis as unknown as { WebSocket: unknown }).WebSocket = WebSocket
}
