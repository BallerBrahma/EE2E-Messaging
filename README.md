# E2EE Messenger

A real end-to-end encrypted messaging platform: a relay server that never sees
plaintext, and a React frontend (light, gradient-accented "Chats/Groups"
bubble UI) that runs either as a desktop client in a native window via
`pywebview`, or as a plain static web app (deployable to GitHub Pages, no
account/server-side changes needed). Key agreement and message encryption
follow the same design as Signal: **X3DH** for the initial handshake and the
**Double Ratchet** for ongoing messages (forward secrecy + post-compromise
security). All cryptographic primitives come from audited libraries only --
no cryptography is hand-rolled anywhere, only the protocol orchestration
around it: the `cryptography` package (X25519, Ed25519, AES-256-GCM, HKDF,
Scrypt) on the Python/desktop side, `@noble/*` (same primitives) on the
TypeScript/web side.

**Architecture**: the relay server and crypto/session/storage logic are
implemented twice, deliberately -- once in Python (`crypto/`, `client/`,
`server/`) for the desktop build, once in TypeScript
(`frontend/src/engine/`) for the browser-native web build -- both speaking
the exact same wire protocol to the same relay server, so a desktop client
and a web client can message each other like any other two accounts. The
desktop client is a single Python process: a background asyncio thread runs
the websocket connection and session logic, and a small bridge class
(`client/api.py`) exposes it to the React+TypeScript frontend (`frontend/`)
rendered in the OS's native webview -- no Electron/Chromium bundle, no
second backend runtime. The web build runs the TypeScript engine directly
in-browser instead, with no Python involved on the client side at all. See
"How it works" below for both.

Features: 1:1 and group chats with dynamic membership, delete-for-everyone,
file attachments, profile pictures, live online/offline presence, pinned
conversations, dark mode, Touch ID / Keychain "remember me" login, backup-
phrase password recovery, and a local (fully offline) spelling checker on
the message box -- all built on the same encrypted-envelope-over-the-ratchet
mechanism (see "Message envelope" below).

## How it works

- **Identity**: each client generates a long-term identity key (X25519 for
  DH + Ed25519 for signing), a signed prekey, and a batch of one-time
  prekeys on first run. Private keys never leave the device; they're
  encrypted at rest with a random 256-bit master key, which is itself
  envelope-encrypted (wrapped) by both a Scrypt-derived password key and a
  key derived from a 12-word backup phrase -- see "Password recovery" below.
- **X3DH**: to message someone for the first time, your client fetches
  their public prekey bundle from the server (even if they're offline) and
  derives a shared secret via 3-4 Diffie-Hellman operations.
- **Double Ratchet**: every message after that uses a self-healing chain of
  keys -- each message has its own key, derived so that compromising one
  message key (or even a whole ratchet state) doesn't expose past or, after
  the next DH step, future messages.
- **Relay server**: routes opaque ciphertext envelopes between clients and
  queues them (SQLite mailbox) if the recipient is offline. It only ever
  sees: usernames, argon2 hashes of a random per-account server-auth token
  (for login -- see "Password recovery" below; never anything derived from
  your actual password), public keys, and ciphertext blobs. It cannot
  decrypt anything.
- **Message envelope**: every ratchet-encrypted plaintext is actually a small
  JSON envelope (`{id, type, group_id, body}`), not a raw string. This is
  what makes deletes, group messages, and attachments possible without
  changing the crypto core at all -- see `client/session_manager.py`.
- **Groups**: pairwise fan-out. There's no group-level key -- the sender
  encrypts one envelope (shared message id) separately to each member's own
  1:1 Double Ratchet session. Simple and fully E2E, at the cost of sending N
  copies for an N-person group. Membership is dynamic: any member can add or
  remove any other member (`group_member_added`/`group_member_removed`
  control envelopes keep everyone's roster in sync); removing someone simply
  stops including them in future fan-out, so they stop receiving new
  messages immediately.
- **Delete for everyone**: sends an encrypted `delete` control envelope
  referencing the original message's id; both sides remove it locally.
- **Attachments**: small files (capped at 10MB) are base64-encoded into an
  `attachment` envelope and travel through the exact same encrypted pipeline
  as text -- no separate blob storage on the server.
- **Profile pictures**: broadcast as a `profile_picture` envelope to every
  contact and group member you already have a session with, encrypted the
  same as everything else. Shown next to names throughout the UI; falls back
  to a colored initial when no picture has been set.
- **Spelling**: the message box uses `pyspellchecker`, a fully local/offline
  word-frequency dictionary -- no draft text is ever sent anywhere before
  you hit send, which matters for an E2EE app specifically (a cloud grammar
  API would leak plaintext before encryption).
- **Pinned conversations**: a purely local, per-device preference (not synced
  to anyone else) -- pinned chats always sort above unpinned ones in the
  sidebar, most-recently-active first within each group.
- **Presence (online/offline)**: the relay server tracks who's currently
  connected (it already needs this to push messages live) and broadcasts
  login/logout to other connected clients, plus a snapshot of who's online
  on your own login. This is presentation-layer only -- presence is never
  part of an encrypted envelope and never touches `client/storage.py`. See
  the security notes below for the metadata tradeoff this implies.
- **Touch ID / Keychain login (`client/keychain.py`)**: your login password
  is also the Scrypt-derived encryption key for your entire local message
  store, so "remember me" doesn't use browser storage or a plain file. If
  you opt in, the password goes into the macOS Keychain (via `keyring`),
  and unlocking it is gated by a real Touch ID/device-passcode prompt (via
  `LocalAuthentication`'s `LAContext`). See the security notes below for
  exactly what this does and doesn't protect against.
- **Password recovery (`client/storage.py`)**: at account creation, a random
  256-bit master key (MK) is generated and wrapped twice -- once by a
  Scrypt-derived key from your login password, once by an HKDF-derived key
  from a 12-word BIP39 backup phrase (via the `mnemonic` package) shown to
  you exactly once, right after registration. Either factor independently
  unwraps MK, which is the key that actually encrypts everything else. This
  also motivated decoupling relay-server auth from your real password: a
  random **server-auth token** is generated alongside MK, MK-encrypted like
  everything else, and used as the value sent to the server's
  register/login instead of your typed password. The result: forgetting
  your password and recovering via the backup phrase needs *zero*
  server-side coordination -- recovering MK recovers the server-auth token
  too, so relay login just keeps working with your new password. Losing
  *both* the password and the backup phrase is still unrecoverable by
  design (see the security notes below).
- **JS bridge (`client/api.py`)**: a single `Api` object passed to
  `webview.create_window(..., js_api=api)`. Every method becomes
  `window.pywebview.api.<method>(...)` from the frontend (wrapped by
  `frontend/src/api.ts` into camelCase). Since `NetworkClient`/
  `SessionManager` are all `async def` but pywebview calls bridge methods
  synchronously, `Api` runs a persistent asyncio event loop on a background
  thread and bridges each call via `asyncio.run_coroutine_threadsafe`.
  Server-pushed events (new messages, presence, group/avatar changes) are
  sent the other direction via `window.evaluate_js(...)`, dispatched to a
  single `window.__onBackendEvent` handler in the frontend.
- **Web build / dual backend (`frontend/src/engine/`)**: the same frontend
  also runs as a plain static web app (deployable to GitHub Pages) with
  *zero* Python involved on the client side. `frontend/src/engine/` is a
  from-scratch TypeScript port of `crypto/`, `client/storage.py`,
  `client/network.py` and `client/session_manager.py` -- same algorithms
  (X3DH, Double Ratchet, envelope-encrypted recovery), same wire protocol,
  running entirely in the browser: `@noble/curves`/`@noble/hashes`/
  `@noble/ciphers` for the crypto (audited pure-TS, chosen over native
  WebCrypto for consistent X25519/Ed25519 support across browsers,
  including Safari), IndexedDB (via `idb`) instead of SQLite for local
  storage. `frontend/src/api.ts` is a small runtime facade: if
  `window.pywebview` is present (desktop build) it delegates to the bridge
  above unchanged; otherwise (web build) it delegates to
  `engine/webApi.ts`. Both implement the identical method surface, so no
  React component needs to know or care which backend it's talking to. The
  relay server itself needs zero changes either way -- it's already
  browser-agnostic JSON-over-websockets, so a desktop client and a web
  client are just two ordinary accounts that can message each other
  normally. Feature parity gaps on the web build: no Touch ID/Keychain
  "remember me" (no browser equivalent without WebAuthn, out of scope for
  now -- `hasBiometricSupport()` just returns `false`, so that UI simply
  never renders), and spelling comes from the browser's native `spellcheck`
  attribute instead of the custom `pyspellchecker`-based one.

## Setup

Backend (Python):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Frontend (Node.js 18+ required):

```bash
cd frontend
npm install
npm run build
```

## Running

Start the relay server (defaults to `ws://localhost:8765`):

```bash
python main_server.py
```

Launch the GUI client (run this in two separate terminals/machines to chat
with yourself for testing, or share the server address with a friend):

```bash
python main_client_web.py
```

For frontend development with hot reload, run `npm run dev` inside
`frontend/` and launch the client with `python main_client_web.py --dev`
instead (points the native window at the Vite dev server).

In the client: create an account (username + password). Right after
registering, you'll see a one-time 12-word backup phrase -- write it down;
you need to check "I've saved this somewhere safe" before continuing, since
it's the only way back in if you forget your password (the "Forgot
password?" link on the login form uses it to unlock your account and set a
new password, with no server-side reset needed). On a Mac with Touch ID,
check "Remember me with Touch ID" before logging in to skip typing your
password next time -- the app will show a "Log in with Touch ID" button on
launch instead of the form ("Not you? Log in differently" reveals the form
again and forgets the saved login). The moon/sun button (login screen, or
next to the sidebar-collapse button once logged in) switches between light
and dark mode; it remembers your choice, defaulting to your system's
preference the first time. The sidebar has "Chats" and "Groups" tabs -- the
"+" button next to them starts a new 1:1 chat or opens the group-creation
dialog depending on which tab is active. The first message to a new contact
triggers the X3DH handshake automatically. In an open conversation:
right-click your own message bubble to delete it for everyone, the "+"
button sends an attachment, and the "ⓘ" button (group chats only) adds or
removes members. Click your own avatar at the top of the sidebar to set a
profile picture. The "☰" button collapses the sidebar so the message view
can use the full window. Misspelled words in the message box get a red
squiggly underline -- right-click one for suggestions. Right-click any
conversation in the sidebar to pin/unpin it -- pinned chats always stay at
the top of the list. Contacts show a green/gray dot on their avatar
reflecting whether they're currently online.

Note: there are no call/video buttons -- this app only does text/attachment
messaging, and we didn't want to ship decorative buttons that don't do
anything.

Local identity/session data is stored per-username under `~/.e2ee_client/`,
encrypted with a master key that's unlockable by either your login password
or your 12-word backup phrase (see "Password recovery" above).

## Deploying

The frontend can also run as a plain static web app instead of the desktop
client -- same UI, same crypto guarantees, backed by the browser-native
engine described in "Web build / dual backend" above. This needs two
independent pieces: the static frontend (GitHub Pages, free) and the relay
server (a small always-on VM, since it's a stateful websocket process --
GitHub Pages can't run it).

**1. Relay server on a free-forever GCP `e2-micro` VM:**

- Create an `e2-micro` instance in an Always-Free-eligible region
  (`us-west1`, `us-central1`, or `us-east1`) -- genuinely free indefinitely,
  not a trial (Google's "Always Free" tier, not the separate $300 trial
  credit). Requires a card on file for identity verification but won't
  charge you as long as you stay within that allowance.
- On the VM: install Python 3, clone this repo, `python3 -m venv .venv &&
  .venv/bin/pip install -r requirements.txt`.
- Install `deploy/e2ee-relay.service` as a systemd unit (see the comments
  in that file) so the server runs on boot and restarts on failure.
- A `https://` GitHub Pages page can only open a `wss://` (not `ws://`)
  websocket -- browsers block the insecure kind as mixed content. Put
  [Caddy](https://caddyserver.com/) in front as a TLS-terminating reverse
  proxy (`deploy/Caddyfile`); it auto-obtains and renews a free Let's
  Encrypt certificate and transparently proxies the websocket upgrade. This
  needs a domain name pointed at the VM's static external IP -- a free
  [DuckDNS](https://www.duckdns.org/) subdomain works fine if you don't
  have one.
- Only port 443 (Caddy) needs to be open in the VM's firewall; the relay
  server itself stays on localhost.

**2. Frontend on GitHub Pages:**

- Push this repo to GitHub, then enable Settings -> Pages -> Source:
  **GitHub Actions** (one-time, in the repo's web UI).
- `.github/workflows/deploy-pages.yml` builds `frontend/` and deploys it on
  every push to `main` -- nothing else to configure; Vite's `base: './'`
  config already works for a GitHub Pages project site without changes.
- On first load, users type the relay server's `wss://your-domain` address
  into the "Server" field on the login screen (same field the desktop
  client uses for `ws://localhost:8765` locally) -- there's no server-side
  coordination needed since account creation happens per-server.

## Tests

```bash
pytest tests/
```

Covers the X3DH handshake, the Double Ratchet (forward secrecy, out-of-order
delivery, tamper detection, state persistence), local-only storage behavior
(pinned-conversation sidebar ordering, password-recovery envelope
encryption -- password and backup-phrase unlock, rejection of wrong
passwords/malformed/foreign recovery phrases, password rotation preserving
the recovery phrase), full integration tests that run a
real relay server and headless clients over real websockets (1:1 and group
message delivery including offline store-and-forward, delete-for-everyone,
byte-for-byte attachment round trips, dynamic group add/remove, profile-
picture fan-out, presence broadcast/snapshot), `tests/test_api.py`, which
exercises `client/api.py` directly (no browser involved) against a real
relay server to confirm the bridge correctly proxies to the backend, and
`tests/test_keychain.py`, which covers Keychain credential storage and the
remembered-username marker (the actual Touch ID prompt needs a real
fingerprint and isn't simulatable in an automated test).

The frontend has its own suite covering the browser-native engine
(`frontend/src/engine/`, see "Web build / dual backend" above):

```bash
cd frontend && npm run build   # tsc type-checking + production bundle
cd frontend && npm run test    # Vitest: crypto/storage/network/session/webApi
```

`npm run test` mirrors the Python suite's structure -- unit tests for each
crypto primitive/X3DH/ratchet port, IndexedDB storage tests (via
`fake-indexeddb`, including the same password-recovery scenarios as the
Python suite), and integration tests that spawn the *real* Python relay
server as a subprocess and drive the TypeScript network/session/webApi
layers against it directly, confirming the two implementations are wire-
compatible.

There's no automated *UI* test suite (React component/rendering
assertions) for either build -- the desktop build's native webview
(WKWebView on macOS) isn't Playwright/CDP-automatable the way Chromium is,
and the web build, while automatable, hasn't had a UI suite written yet.
Verifying visual/UI changes means running the app directly (either
`python main_client_web.py`, or `npm run build && npm run preview` for the
web build) and using it.

## Security notes / limitations

This is a personal/educational project, **not independently audited**.
Before relying on it for anything sensitive, be aware:

- No safety-number / key-fingerprint verification UI yet, so there's no way
  to manually verify you're talking to who you think you are (protection
  against a malicious/compromised server impersonating a contact's keys).
- **Delete-for-everyone is cooperative, not cryptographically enforced** --
  same tradeoff Signal makes. It tells a normal client to remove the
  message; nothing stops a modified client from ignoring that and keeping a
  copy (e.g. a screenshot before deletion arrives).
- **Presence reveals who's online to the server and to other connected
  clients.** The server already knows who's logged in (it routes messages by
  username), so this isn't a new category of exposure, but it does mean
  "online now" is visible metadata, not something hidden behind E2E
  encryption -- there's no way to appear offline while connected.
- Group fan-out means message-sending cost scales linearly with group size
  (no shared group key/Sender Keys optimization). This also applies to
  adding/removing members and profile picture updates.
- Removing someone from a group stops sending them *future* messages, but
  doesn't (and cryptographically can't) revoke anything they already
  received or decrypted -- same limitation Signal-style group membership has
  without a full key-rotation scheme.
- Attachments are capped at 10MB, profile pictures at 2MB, both travel
  inline through the same relay mailbox as text; there's no resumable
  upload or dedicated blob storage.
- The relay server's login credential and the E2E identity keys are fully
  decoupled: the server only ever sees an argon2 hash of a random
  server-auth token that has nothing to do with your typed password (see
  "Password recovery" above) -- a server compromise exposes account access
  at most, never message content, private keys, or your real password.
- **Losing your password is recoverable via the 12-word backup phrase shown
  once at registration** (see "Password recovery" above); losing *both* the
  password and the backup phrase means your local identity and message
  history are unrecoverable by design -- there is no backdoor and the
  server never has the ability to decrypt anything on your behalf. Treat
  the backup phrase like a crypto-wallet seed: write it down somewhere
  durable and offline, not in a screenshot or a cloud note. Separately,
  if you've used "Remember me with Touch ID", the password is retrieved
  from the Keychain, so losing the password itself isn't fatal on that
  device either (but *is* fatal there if you also revoke/forget the
  Keychain entry -- the backup phrase is the only recovery path that
  doesn't depend on a specific device).
- **"Remember me with Touch ID" gates a normal Keychain secret with an
  application-level check, not a hardware-enforced biometric ACL on the
  Keychain item itself.** In practice: `client/keychain.py`'s
  `authenticate_with_biometrics()` must return `True` before the code path
  that reads the saved password runs. This stops someone who picks up your
  unlocked laptop from opening the app as you -- the realistic threat model
  for this convenience feature -- but it does not stop a maliciously
  modified build of this app's own code from skipping that check and
  reading the Keychain entry directly (the true Apple-recommended pattern
  binds a `kSecAccessControlBiometryCurrentSet` ACL directly to the
  Keychain item at the Security-framework level, which is more native code
  than is justified for a personal-project convenience feature). Only
  opt in on a device you trust.
