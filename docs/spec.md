# Sweet Cookie Brunch — Cookie Extraction Spec

## Goal

Standardize cookie extraction across Peter’s TypeScript tools:
- `@steipete/sweet-cookie` (library): one API to load cookies from inline payloads + local browsers.
- `apps/extension` (Chrome MV3): “escape hatch” exporter for cases where native/DB reads fail.

Primary use-cases:
- One implementation used by `oracle`, `sweetlink`, `summarize`, etc.
- Escape hatches for “native module pain” (Node vs Bun vs CI) + keychain prompts.
- Windows/locked-down environments where DB-based reads are flaky (DPAPI/app-bound cookies) → extension export.

## Non-goals

- Re-implement every Chromium encryption scheme across platforms.
- Cross-profile extraction via the extension (extensions can’t read other Chrome profiles).
- Bypassing browser security boundaries (extension reads only what it’s permitted to read).
- Headless automation. (Library is “read cookies”, not “drive browser”.)

## Library (`@steipete/sweet-cookie`)

### API surface

Exports:
- `getCookies(options: GetCookiesOptions): Promise<{ cookies: Cookie[]; warnings: string[] }>`
- `toCookieHeader(cookies: Cookie[], options?): string`

High-signal options:
- `url`: primary target URL (host drives filtering)
- `origins`: extra origins (OAuth, multi-domain auth)
- `names`: allowlist cookie names
- `browsers`: ordered sources (`chrome|safari|firefox`)
- `mode`: `merge` (default) or `first`
- `profile` / `chromeProfile`: Chrome profile name/path
- `firefoxProfile`: Firefox profile name/path
- `includeExpired`: include expired cookies
- Inline inputs (escape hatch):
  - `inlineCookiesJson`, `inlineCookiesBase64`, `inlineCookiesFile`
  - `oracleInlineFallback`: also tries `~/.oracle/cookies.{json,base64}`

### Provider order

1) Inline sources (if any). First non-empty wins.
2) Local browsers in declared order:
   - **Chrome**
     - `chrome-cookies-secure` if installed + loadable (optional dependency)
     - macOS fallback: copy DB → query via `sqlite3` CLI (Node) or `bun:sqlite` (Bun) → decrypt via Keychain `security` (Chrome Safe Storage)
     - Windows: expect failures; prefer inline/export
   - **Firefox**
     - Bun: `bun:sqlite` (no native Node sqlite bindings)
     - Node: `sqlite3` CLI (no node-sqlite3 dependency)
   - **Safari**
     - parse `Cookies.binarycookies` directly (no WebKit db dependency)

### Output contract

`Cookie[]` is “CDP-ish” and tool-friendly:
- `name`, `value`, `domain`, `path`
- optional: `expires` (unix seconds), `secure`, `httpOnly`, `sameSite`
- `source` includes `browser` and optional `profile` (for debugging)

## Extension (`apps/extension`)

## Outputs (formats)

### 1) Oracle inline cookies (preferred)

Oracle accepts `Protocol.Network.CookieParam[]` (“CDP cookie params”).

Sweet Cookie exports:
- `cookies`: array of objects compatible with `Protocol.Network.CookieParam`
- `meta`: versioning + provenance

Example shape:
```json
{
  "version": 1,
  "generatedAt": "2025-12-27T18:00:00.000Z",
  "source": "sweet-cookie",
  "browser": "chrome",
  "targetUrl": "https://chatgpt.com/",
  "origins": ["https://chatgpt.com/"],
  "cookies": [
    {
      "name": "__Secure-next-auth.session-token",
      "value": "…",
      "domain": "chatgpt.com",
      "path": "/",
      "secure": true,
      "httpOnly": true,
      "sameSite": "Lax",
      "expires": 1767225600
    }
  ]
}
```

Notes:
- `oracle` will normalize missing fields and can attach `url` if needed; keeping `domain` is fine, but if `url` is set, Oracle will drop `domain` before calling CDP.
- `expires` should be unix seconds when available; omit when session cookie.

### 2) Base64 payload (clipboard-friendly)

Same JSON as (1), then base64-encode the full JSON string.

Use-cases:
- paste into `ORACLE_BROWSER_COOKIES_JSON` (if you want to keep env-only flows)
- quick transfer over chat

### 3) Puppeteer cookies (optional)

Some callers use Puppeteer’s cookie shape (`Secure`/`HttpOnly` capitalization). This is optional since Oracle prefers CDP `CookieParam`.

## Inputs / UI

Popup UX (minimal):
- Target URL input (default: current tab URL)
- Extra origins (multi-line), optional
- Cookie allowlist (comma-separated names), optional
- “Copy JSON”, “Copy base64”, “Download .json”
- “Dry preview” table: cookie count + domains + redacted values (first 6 chars)

Defaults:
- `targetUrl` = active tab URL
- `origins` = `{targetUrl.origin}` plus any configured extras
- `allowlist` = empty (export all) unless a preset is chosen

Presets (optional, for speed):
- ChatGPT (chatgpt.com)
- Gemini (google.com / gemini.google.com)
- X (x.com / twitter.com)

## Permissions model (Manifest V3)

We need:
- `cookies` permission
- host permissions for the relevant domains/origins

Prefer **optional host permissions** requested at runtime:
- On “Export”, compute required origins and call `chrome.permissions.request({ origins })`
- If denied, show a clear error and a “Grant permissions” retry button

Why:
- Keeps install footprint small.
- Makes the “this is reading cookies for these domains” explicit.

## Cookie collection algorithm

Inputs:
- `origins[]` (fully-qualified, https preferred)
- optional `allowlistNames: Set<string>`

Steps:
1) Normalize origins (force trailing `/`, drop query/hash)
2) For each origin:
   - Derive `domain` candidates:
     - If origin hostname is `localhost` or an IP: query via `url` matching (Chrome cookies API supports `url` filter).
     - Else: query `chrome.cookies.getAll({ url: origin })` (preferred; avoids home-grown domain logic).
3) Merge + dedupe:
   - key = `${cookie.name}|${cookie.domain}|${cookie.path}|${cookie.storeId}`
4) Filter:
   - if allowlist is present: keep only matching cookie names
5) Serialize:
   - Map Chrome extension cookie fields → CDP-ish `CookieParam` fields:
     - `name`, `value`, `domain`, `path`
     - `secure`, `httpOnly`
     - `sameSite` (map Chrome enum to `Strict|Lax|None` strings)
     - `expires`: from `expirationDate` (seconds); omit if missing
   - Do not persist raw cookies beyond the export action

Important: avoid re-implementing RFC cookie matching/order. If we export for reuse (Oracle/SweetLink), “set cookies” is what matters; ordering is not.

## Security / safety constraints

- No automatic/background exports. User gesture only.
- No network exfiltration. No remote endpoints.
- No logging raw cookie values (ever). UI should show redacted values only.
- Offer “allowlist names” as a first-class control.
- Prefer in-memory only. If we add “save presets”, store *only* domains/origins/allowlists, never values.

## Integration targets

### Oracle

- File: download `sweet-cookie.cookies.json`, then:
  - `oracle --engine browser --browser-inline-cookies-file sweet-cookie.cookies.json …`
- Or base64:
  - set `ORACLE_BROWSER_COOKIES_JSON=<base64>`

### SweetLink

SweetLink currently syncs via `chrome-cookies-secure` (native). Sweet Cookie is the escape hatch when native bindings or keychain access fails:
- Export cookies for the app origin and OAuth origins in `cookieMappings`
- SweetLink can accept an inline cookies file/env in a future addition (not in scope for this doc)

## Versioning

- `version` integer in the exported JSON.
- Bump only on breaking schema changes.
- Include `generatedAt`, `targetUrl`, `origins`, `source`.

## Open questions (decide early)

- Do we want a “cookie names allowlist” preset per target (ChatGPT/Gemini/X), or always export all and let tools filter?
- Do we ship a CLI companion (`sweet-cookie dump --url …`) that talks to the extension via native messaging / localhost? (likely no; keep extension-only first.)
- Should we support multiple cookie stores (`storeId`) explicitly, or just merge everything? (default merge.)
