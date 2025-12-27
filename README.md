# Sweet Cookie

Cookie extraction, Peter-style: boring API, lots of escape hatches.

Two deliverables:
- `@steipete/sweet-cookie` (Node): unified cookie read API (Chrome/Firefox/Safari + inline payloads).
- `apps/extension` (Chrome MV3): cookie exporter for when native readers fail (copy JSON/base64, download file).

## Why

We keep hitting three realities:
- Chrome cookies: “secure / app-bound” + encryption + profile DB locks.
- Native deps: rebuilds + ABI + runtime differences (Node vs Bun).
- Most tools only need “cookie params”, not a whole browser automation stack.

Sweet Cookie standardizes on one flow:
1) Inline cookies (exported by the extension) — most reliable.
2) Best-effort local reads:
   - Chrome: `chrome-cookies-secure` (if installed) + macOS `node:sqlite`/`bun:sqlite` + keychain fallback
   - Firefox: `node:sqlite` (Node) or `bun:sqlite` (Bun)
   - Safari: binarycookies parsing

## Install

Requirements:
- Node `>=22` (repo default)
- `pnpm`
- No external `sqlite3` CLI needed (uses runtime SQLite: `node:sqlite` / `bun:sqlite`)

```bash
pnpm i
```

## Node API

```ts
import { getCookies, toCookieHeader } from '@steipete/sweet-cookie';

const { cookies, warnings } = await getCookies({
  url: 'https://chatgpt.com/',
  names: ['__Secure-next-auth.session-token'],
  browsers: ['chrome', 'safari', 'firefox'],

  // Chrome:
  profile: 'Default', // alias for chromeProfile

  // Inline “escape hatch”:
  oracleInlineFallback: true,
});

const header = toCookieHeader(cookies, { dedupeByName: true });
```

Options (high-signal):
- `url`: target URL (drives default origin filtering)
- `origins`: extra origins to consider (OAuth, etc)
- `names`: allowlist cookie names
- `browsers`: source order (`chrome|safari|firefox`)
- `mode`: `merge` (default) or `first`
- `profile` / `chromeProfile`: Chrome profile name/path for `chrome-cookies-secure`
- `firefoxProfile`: Firefox profile name/path
- `safariCookiesFile`: override path to `Cookies.binarycookies` (tests/debug)
- Inline sources:
  - `inlineCookiesJson`, `inlineCookiesBase64`, `inlineCookiesFile`
  - `oracleInlineFallback`: also tries `~/.oracle/cookies.{json,base64}`

Env:
- `SWEET_COOKIE_BROWSERS` / `SWEET_COOKIE_SOURCES`: `chrome,safari,firefox`
- `SWEET_COOKIE_MODE`: `merge|first`
- `SWEET_COOKIE_CHROME_PROFILE`, `SWEET_COOKIE_FIREFOX_PROFILE`
- `SWEET_COOKIE_ORACLE_FALLBACK`: `1`

## Inline Cookie Payload

Accepts either:
- a plain `Cookie[]`
- or `{ cookies: Cookie[] }`

This matches the extension export (`docs/spec.md`) and is close to CDP cookie params:

```jsonc
{
  "version": 1,
  "generatedAt": "2025-12-27T18:00:00.000Z",
  "source": "sweet-cookie",
  "browser": "chrome",
  "targetUrl": "https://chatgpt.com/",
  "origins": ["https://chatgpt.com/"],
  "cookies": [{ "name": "sid", "value": "…", "domain": "chatgpt.com", "path": "/" }]
}
```

## Chrome Extension (MV3)

Build + load:

```bash
pnpm -C apps/extension build
```

Then load `apps/extension/dist` via `chrome://extensions` → “Load unpacked”.

Export modes:
- Copy JSON
- Copy base64
- Download `.json`

Security stance:
- user gesture only
- no network calls
- no logging raw cookie values
- optional host permissions requested at export time

## Troubleshooting

Native deps (Chrome reads):
- `chrome-cookies-secure` pulls in native `sqlite3` + `keytar`.
- If install/rebuild hurts, use the extension export.

Bun:
- `bun:sqlite` is used for Firefox (and Chrome mac fallback).
- Chrome via `chrome-cookies-secure` is optional; if native deps hurt, prefer extension exports.

Firefox:
- uses `node:sqlite` (Node) or `bun:sqlite` (Bun).

## Related / prior art

- `../sweetlink`: uses `chrome-cookies-secure` for cookie sync (native).
- `../oracle`: uses `chrome-cookies-secure` for browser-session reuse (native).
- `../bird` + `../summarize`: domain-specific cookie extraction (sqlite3 CLI + custom parsing).
- `../oss/get-cookie`: feature-rich, but native-heavy (`better-sqlite3`, etc) and different ergonomics.

## Dev

```bash
pnpm build
pnpm typecheck
pnpm lint
pnpm test
pnpm test:bun
```
