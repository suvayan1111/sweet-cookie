import { createDecipheriv, pbkdf2Sync } from 'node:crypto';
import { copyFileSync, existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
import { execCapture } from '../util/exec.js';
import { normalizeExpiration } from '../util/expire.js';
import { hostMatchesCookieDomain } from '../util/hostMatch.js';
import { isBunRuntime } from '../util/runtime.js';
export async function getCookiesFromChromeSqliteMac(options, origins, allowlistNames) {
    const warnings = [];
    const dbPath = resolveChromeCookiesDb(options.profile);
    if (!dbPath) {
        warnings.push('Chrome cookies database not found.');
        return { cookies: [], warnings };
    }
    const tempDir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-chrome-'));
    const tempDbPath = path.join(tempDir, 'Cookies');
    try {
        copyFileSync(dbPath, tempDbPath);
        copySidecar(dbPath, `${tempDbPath}-wal`, '-wal');
        copySidecar(dbPath, `${tempDbPath}-shm`, '-shm');
    }
    catch (error) {
        rmSync(tempDir, { recursive: true, force: true });
        warnings.push(`Failed to copy Chrome cookie DB: ${error instanceof Error ? error.message : String(error)}`);
        return { cookies: [], warnings };
    }
    try {
        const hosts = origins.map((o) => new URL(o).hostname);
        const where = buildHostWhereClause(hosts);
        const passwordResult = await execCapture('security', ['find-generic-password', '-w', '-s', 'Chrome Safe Storage'], { timeoutMs: 3_000 });
        if (passwordResult.code !== 0) {
            warnings.push(`Failed to read macOS Keychain (Chrome Safe Storage): ${passwordResult.stderr.trim() || `exit ${passwordResult.code}`}`);
            return { cookies: [], warnings };
        }
        const chromePassword = passwordResult.stdout.trim();
        if (!chromePassword) {
            warnings.push('macOS Keychain returned an empty Chrome Safe Storage password.');
            return { cookies: [], warnings };
        }
        const sql = `SELECT name, value, host_key, path, expires_utc, is_secure, is_httponly, samesite, encrypted_value ` +
            `FROM cookies WHERE (${where}) ORDER BY expires_utc DESC;`;
        let cookies;
        if (isBunRuntime()) {
            const bunResult = await queryChromeCookiesWithBunSqlite(tempDbPath, sql);
            if (!bunResult.ok) {
                warnings.push(`bun:sqlite failed reading Chrome cookies: ${bunResult.error}`);
                return { cookies: [], warnings };
            }
            cookies = collectChromeCookiesFromRows(bunResult.rows, chromePassword, options, hosts, allowlistNames);
        }
        else {
            const nodeResult = await queryChromeCookiesWithNodeSqlite(tempDbPath, sql);
            if (!nodeResult.ok) {
                warnings.push(`node:sqlite failed reading Chrome cookies: ${nodeResult.error}`);
                return { cookies: [], warnings };
            }
            cookies = collectChromeCookiesFromRows(nodeResult.rows, chromePassword, options, hosts, allowlistNames);
        }
        if (!options.includeExpired) {
            const now = Math.floor(Date.now() / 1000);
            cookies = cookies.filter((cookie) => !isExpired(cookie.expires, now));
        }
        return { cookies: dedupeCookies(cookies), warnings };
    }
    finally {
        rmSync(tempDir, { recursive: true, force: true });
    }
}
function copySidecar(sourceDbPath, target, suffix) {
    const sidecar = `${sourceDbPath}${suffix}`;
    if (!existsSync(sidecar))
        return;
    try {
        copyFileSync(sidecar, target);
    }
    catch {
        // ignore
    }
}
function resolveChromeCookiesDb(profile) {
    const home = homedir();
    /* c8 ignore next */
    const roots = process.platform === 'darwin'
        ? [path.join(home, 'Library', 'Application Support', 'Google', 'Chrome')]
        : [];
    const candidates = [];
    if (profile && looksLikePath(profile)) {
        const expanded = expandPath(profile);
        const stat = safeStat(expanded);
        if (stat?.isFile())
            return expanded;
        candidates.push(path.join(expanded, 'Cookies'));
        candidates.push(path.join(expanded, 'Network', 'Cookies'));
    }
    else {
        const profileDir = profile && profile.trim().length > 0 ? profile.trim() : 'Default';
        for (const root of roots) {
            candidates.push(path.join(root, profileDir, 'Cookies'));
            candidates.push(path.join(root, profileDir, 'Network', 'Cookies'));
        }
    }
    for (const candidate of candidates) {
        if (existsSync(candidate))
            return candidate;
    }
    return null;
}
function safeStat(candidate) {
    try {
        return statSync(candidate);
    }
    catch {
        return null;
    }
}
function expandPath(input) {
    if (input.startsWith('~/'))
        return path.join(homedir(), input.slice(2));
    return path.isAbsolute(input) ? input : path.resolve(process.cwd(), input);
}
function looksLikePath(value) {
    return value.includes('/') || value.includes('\\');
}
async function queryChromeCookiesWithNodeSqlite(dbPath, sql) {
    try {
        const { DatabaseSync } = await import('node:sqlite');
        const db = new DatabaseSync(dbPath, { readOnly: true });
        try {
            const rows = db.prepare(sql).all();
            return { ok: true, rows };
        }
        finally {
            db.close();
        }
    }
    catch (error) {
        return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
}
async function queryChromeCookiesWithBunSqlite(dbPath, sql) {
    try {
        const { Database } = await import('bun:sqlite');
        const db = new Database(dbPath, { readonly: true });
        try {
            const rows = db.query(sql).all();
            return { ok: true, rows };
        }
        finally {
            db.close();
        }
    }
    catch (error) {
        return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
}
function collectChromeCookiesFromRows(rows, password, options, hosts, allowlistNames) {
    const cookies = [];
    for (const row of rows) {
        const name = typeof row.name === 'string' ? row.name : null;
        if (!name)
            continue;
        if (allowlistNames && allowlistNames.size > 0 && !allowlistNames.has(name))
            continue;
        const hostKey = typeof row.host_key === 'string' ? row.host_key : null;
        if (!hostKey)
            continue;
        if (!hostMatchesAny(hosts, hostKey))
            continue;
        const rowPath = typeof row.path === 'string' ? row.path : '';
        const valueString = typeof row.value === 'string' ? row.value : null;
        let value = valueString;
        if (value === null || value.length === 0) {
            const encryptedBytes = getEncryptedBytes(row);
            if (!encryptedBytes)
                continue;
            value = decryptChromiumCookieValueMac(encryptedBytes, password);
        }
        if (value === null)
            continue;
        const expiresRaw = typeof row.expires_utc === 'number' ? row.expires_utc : tryParseInt(row.expires_utc);
        const expires = normalizeExpiration(expiresRaw ?? undefined);
        const secure = row.is_secure === 1 || row.is_secure === '1' || row.is_secure === true;
        const httpOnly = row.is_httponly === 1 || row.is_httponly === '1' || row.is_httponly === true;
        const sameSite = normalizeChromiumSameSite(row.samesite);
        const source = { browser: 'chrome' };
        if (options.profile)
            source.profile = options.profile;
        const cookie = {
            name,
            value,
            domain: hostKey.startsWith('.') ? hostKey.slice(1) : hostKey,
            path: rowPath || '/',
            secure,
            httpOnly,
            source,
        };
        if (expires !== undefined)
            cookie.expires = expires;
        if (sameSite !== undefined)
            cookie.sameSite = sameSite;
        cookies.push(cookie);
    }
    return cookies;
}
function tryParseInt(value) {
    if (typeof value !== 'string')
        return null;
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : null;
}
function normalizeChromiumSameSite(value) {
    if (typeof value === 'number') {
        if (value === 2)
            return 'Strict';
        if (value === 1)
            return 'Lax';
        if (value === 0)
            return 'None';
        return undefined;
    }
    if (typeof value === 'string') {
        const parsed = Number.parseInt(value, 10);
        if (Number.isFinite(parsed))
            return normalizeChromiumSameSite(parsed);
        const normalized = value.toLowerCase();
        if (normalized === 'strict')
            return 'Strict';
        if (normalized === 'lax')
            return 'Lax';
        if (normalized === 'none' || normalized === 'no_restriction')
            return 'None';
    }
    return undefined;
}
function getEncryptedBytes(row) {
    const raw = row.encrypted_value;
    if (raw instanceof Uint8Array)
        return raw;
    return null;
}
function decryptChromiumCookieValueMac(encryptedValue, password) {
    try {
        const buf = Buffer.from(encryptedValue);
        const prefix = buf.subarray(0, 3).toString('utf8');
        const hasVersionPrefix = /^v\d\d$/.test(prefix);
        if (!hasVersionPrefix) {
            return cleanValue(buf.toString('utf8'));
        }
        const value = buf.subarray(3);
        if (value.length === 0)
            return '';
        const key = pbkdf2Sync(password, 'saltysalt', 1003, 16, 'sha1');
        const iv = Buffer.alloc(16, 0x20);
        const decipher = createDecipheriv('aes-128-cbc', key, iv);
        decipher.setAutoPadding(false);
        let decrypted = decipher.update(value);
        decipher.final();
        decrypted = removePkcs7Padding(decrypted);
        return cleanValue(decrypted.toString('utf8'));
    }
    catch {
        return null;
    }
}
function removePkcs7Padding(value) {
    if (!value.length)
        return value;
    const padding = value[value.length - 1];
    if (!padding || padding > 16)
        return value;
    return value.subarray(0, value.length - padding);
}
function cleanValue(value) {
    let i = 0;
    while (i < value.length && value.charCodeAt(i) < 0x20)
        i += 1;
    return value.slice(i);
}
function isExpired(expires, nowSeconds) {
    if (!expires)
        return false;
    return expires > 0 && expires < nowSeconds;
}
function buildHostWhereClause(hosts) {
    const clauses = [];
    for (const host of hosts) {
        const escaped = sqlLiteral(host);
        const escapedDot = sqlLiteral(`.${host}`);
        const escapedLike = sqlLiteral(`%.${host}`);
        clauses.push(`host_key = ${escaped}`);
        clauses.push(`host_key = ${escapedDot}`);
        clauses.push(`host_key LIKE ${escapedLike}`);
    }
    return clauses.length ? clauses.join(' OR ') : '1=0';
}
function sqlLiteral(value) {
    const escaped = value.replaceAll("'", "''");
    return `'${escaped}'`;
}
function hostMatchesAny(hosts, cookieHost) {
    const cookieDomain = cookieHost.startsWith('.') ? cookieHost.slice(1) : cookieHost;
    return hosts.some((host) => hostMatchesCookieDomain(host, cookieDomain));
}
function dedupeCookies(cookies) {
    const merged = new Map();
    for (const cookie of cookies) {
        const key = `${cookie.name}|${cookie.domain ?? ''}|${cookie.path ?? ''}`;
        if (!merged.has(key))
            merged.set(key, cookie);
    }
    return Array.from(merged.values());
}
//# sourceMappingURL=chromeSqliteMac.js.map