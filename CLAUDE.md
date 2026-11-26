# CaddyProxyManager: notes for Claude

## UI theme

- **Always use a light theme by default.** Never follow the system's dark
  mode automatically (no `prefers-color-scheme: dark` defaults).
- Offer dark mode only as an option the user turns on (the user menu's
  "Dark mode", remembered in localStorage under `hsl-suite-theme`), or when
  someone asks for it.
- The shared look (tokens, frame, app switcher, user menu, sign-in card, the
  H mark) is the HSL Suite kit in `web/src/hsl-ui/`, synced from
  hackspacelabs-web with `scripts/sync-hsl-ui.sh`. Never edit that copy;
  change the kit there and sync.
- This applies to everything built here: the CPM UI, artifacts, pages,
  reports and screenshots.
