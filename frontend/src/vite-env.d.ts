/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Default value for the login screen's "Server" field, baked in at build
   * time (e.g. by .github/workflows/deploy-pages.yml for the GitHub Pages
   * build). Falls back to the local-dev relay address when unset. */
  readonly VITE_DEFAULT_SERVER_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
