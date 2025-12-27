import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';

import type { Cookie, CookieSameSite, GetCookiesResult } from '../types.js';
import { execCapture } from '../util/exec.js';
import { hostMatchesCookieDomain } from '../util/hostMatch.js';
import { isBunRuntime } from '../util/runtime.js';

export async function getCookiesFromFirefox(
	options: { profile?: string; includeExpired?: boolean },
	origins: string[],
	allowlistNames: Set<string> | null
): Promise<GetCookiesResult> {
	const warnings: string[] = [];
	const dbPath = resolveFirefoxCookiesDb(options.profile);
	if (!dbPath) {
		warnings.push('Firefox cookies database not found.');
		return { cookies: [], warnings };
	}

	const hosts = origins.map((o) => new URL(o).hostname);
	const now = Math.floor(Date.now() / 1000);
	const where = buildHostWhereClause(hosts);
	const expiryClause = options.includeExpired ? '' : ` AND (expiry = 0 OR expiry > ${now})`;
	const sql =
		`SELECT name, value, host, path, expiry, isSecure, isHttpOnly, sameSite ` +
		`FROM moz_cookies WHERE (${where})${expiryClause} ORDER BY expiry DESC;`;

	if (isBunRuntime()) {
		const bunResult = await queryFirefoxCookiesWithBunSqlite(dbPath, sql);
		if (bunResult.ok) {
			return {
				cookies: dedupeCookies(
					collectFirefoxCookiesFromRows(bunResult.rows, options, hosts, allowlistNames)
				),
				warnings,
			};
		}
		warnings.push(`bun:sqlite failed reading Firefox cookies: ${bunResult.error}`);
	}

	const sep = '\u001F';
	const result = await execCapture('sqlite3', ['-noheader', `-separator`, sep, dbPath, sql], {
		timeoutMs: 5_000,
	});
	if (result.code !== 0) {
		warnings.push(
			`sqlite3 failed reading Firefox cookies: ${result.stderr.trim() || `exit ${result.code}`}`
		);
		return { cookies: [], warnings };
	}

	const cookies = collectFirefoxCookiesFromSqlite3Stdout(
		result.stdout,
		sep,
		options,
		hosts,
		allowlistNames
	);
	return { cookies: dedupeCookies(cookies), warnings };
}

type FirefoxRow = {
	name?: unknown;
	value?: unknown;
	host?: unknown;
	path?: unknown;
	expiry?: unknown;
	isSecure?: unknown;
	isHttpOnly?: unknown;
	sameSite?: unknown;
};

async function queryFirefoxCookiesWithBunSqlite(
	dbPath: string,
	sql: string
): Promise<{ ok: true; rows: FirefoxRow[] } | { ok: false; error: string }> {
	try {
		const { Database } = await import('bun:sqlite');
		const db = new Database(dbPath, { readonly: true });
		try {
			const rows = db.query(sql).all() as FirefoxRow[];
			return { ok: true, rows };
		} finally {
			db.close();
		}
	} catch (error) {
		return { ok: false, error: error instanceof Error ? error.message : String(error) };
	}
}

function collectFirefoxCookiesFromRows(
	rows: FirefoxRow[],
	options: { profile?: string; includeExpired?: boolean },
	hosts: string[],
	allowlistNames: Set<string> | null
): Cookie[] {
	const now = Math.floor(Date.now() / 1000);
	const cookies: Cookie[] = [];

	for (const row of rows) {
		const name = typeof row.name === 'string' ? row.name : null;
		const value = typeof row.value === 'string' ? row.value : null;
		const host = typeof row.host === 'string' ? row.host : null;
		const cookiePath = typeof row.path === 'string' ? row.path : '';

		if (!name || value === null || !host) continue;
		if (allowlistNames && allowlistNames.size > 0 && !allowlistNames.has(name)) continue;
		if (!hostMatchesAny(hosts, host)) continue;

		const expiryText =
			typeof row.expiry === 'number'
				? String(row.expiry)
				: typeof row.expiry === 'string'
					? row.expiry
					: undefined;
		const expires = normalizeFirefoxExpiry(expiryText);
		if (!options.includeExpired && expires && expires < now) continue;

		const isSecure = row.isSecure === 1 || row.isSecure === '1' || row.isSecure === true;
		const isHttpOnly = row.isHttpOnly === 1 || row.isHttpOnly === '1' || row.isHttpOnly === true;

		const cookie: Cookie = {
			name,
			value,
			domain: host.startsWith('.') ? host.slice(1) : host,
			path: cookiePath || '/',
			secure: isSecure,
			httpOnly: isHttpOnly,
		};

		if (expires !== undefined) cookie.expires = expires;
		const normalizedSameSite = normalizeFirefoxSameSite(
			typeof row.sameSite === 'number'
				? String(row.sameSite)
				: typeof row.sameSite === 'string'
					? row.sameSite
					: undefined
		);
		if (normalizedSameSite !== undefined) cookie.sameSite = normalizedSameSite;

		const source: NonNullable<Cookie['source']> = { browser: 'firefox' };
		if (options.profile) source.profile = options.profile;
		cookie.source = source;

		cookies.push(cookie);
	}

	return cookies;
}

function collectFirefoxCookiesFromSqlite3Stdout(
	stdout: string,
	sep: string,
	options: { profile?: string; includeExpired?: boolean },
	hosts: string[],
	allowlistNames: Set<string> | null
): Cookie[] {
	const now = Math.floor(Date.now() / 1000);
	const cookies: Cookie[] = [];

	const lines = stdout.split('\n').map((l) => l.trimEnd());
	for (const line of lines) {
		if (!line) continue;
		const parts = line.split(sep);
		const [name, value, host, cookiePath, expiry, isSecure, isHttpOnly, sameSite] = parts;
		if (!name || value === undefined || !host) continue;
		if (allowlistNames && allowlistNames.size > 0 && !allowlistNames.has(name)) continue;
		if (!hostMatchesAny(hosts, host)) continue;
		const expires = normalizeFirefoxExpiry(expiry);
		if (!options.includeExpired && expires && expires < now) continue;

		const cookie: Cookie = {
			name,
			value,
			domain: host.startsWith('.') ? host.slice(1) : host,
			path: cookiePath || '/',
			secure: isSecure === '1',
			httpOnly: isHttpOnly === '1',
		};

		if (expires !== undefined) cookie.expires = expires;
		const normalizedSameSite = normalizeFirefoxSameSite(sameSite);
		if (normalizedSameSite !== undefined) cookie.sameSite = normalizedSameSite;

		const source: NonNullable<Cookie['source']> = { browser: 'firefox' };
		if (options.profile) source.profile = options.profile;
		cookie.source = source;

		cookies.push(cookie);
	}

	return cookies;
}

function resolveFirefoxCookiesDb(profile?: string): string | null {
	const home = homedir();
	// biome-ignore lint/complexity/useLiteralKeys: process.env is an index signature under strict TS.
	const appData = process.env['APPDATA'];
	/* c8 ignore next 10 */
	const roots =
		process.platform === 'darwin'
			? [path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles')]
			: process.platform === 'linux'
				? [path.join(home, '.mozilla', 'firefox')]
				: process.platform === 'win32'
					? appData
						? [path.join(appData, 'Mozilla', 'Firefox', 'Profiles')]
						: []
					: [];

	if (profile && looksLikePath(profile)) {
		const candidate = profile.endsWith('cookies.sqlite')
			? profile
			: path.join(profile, 'cookies.sqlite');
		return existsSync(candidate) ? candidate : null;
	}

	for (const root of roots) {
		if (!root || !existsSync(root)) continue;
		if (profile) {
			const candidate = path.join(root, profile, 'cookies.sqlite');
			if (existsSync(candidate)) return candidate;
			continue;
		}

		const entries = safeReaddir(root);
		const defaultRelease = entries.find((e) => e.includes('default-release'));
		const picked = defaultRelease ?? entries[0];
		if (!picked) continue;
		const candidate = path.join(root, picked, 'cookies.sqlite');
		if (existsSync(candidate)) return candidate;
	}

	return null;
}

function safeReaddir(dir: string): string[] {
	try {
		return readdirSync(dir, { withFileTypes: true })
			.filter((e: { isDirectory: () => boolean }) => e.isDirectory())
			.map((e: { name: string }) => e.name);
	} catch {
		return [];
	}
}

function looksLikePath(value: string): boolean {
	return value.includes('/') || value.includes('\\');
}

function buildHostWhereClause(hosts: string[]): string {
	const clauses: string[] = [];
	for (const host of hosts) {
		const escaped = sqlLiteral(host);
		const escapedDot = sqlLiteral(`.${host}`);
		const escapedLike = sqlLiteral(`%.${host}`);
		clauses.push(`host = ${escaped}`);
		clauses.push(`host = ${escapedDot}`);
		clauses.push(`host LIKE ${escapedLike}`);
	}
	return clauses.length ? clauses.join(' OR ') : '1=0';
}

function sqlLiteral(value: string): string {
	const escaped = value.replaceAll("'", "''");
	return `'${escaped}'`;
}

function normalizeFirefoxExpiry(expiry?: string): number | undefined {
	if (!expiry) return undefined;
	const value = Number.parseInt(expiry, 10);
	if (!Number.isFinite(value) || value <= 0) return undefined;
	return value;
}

function normalizeFirefoxSameSite(raw?: string): CookieSameSite | undefined {
	if (!raw) return undefined;
	const value = Number.parseInt(raw, 10);
	if (Number.isFinite(value)) {
		if (value === 2) return 'Strict';
		if (value === 1) return 'Lax';
		if (value === 0) return 'None';
	}
	const normalized = raw.toLowerCase();
	if (normalized === 'strict') return 'Strict';
	if (normalized === 'lax') return 'Lax';
	if (normalized === 'none') return 'None';
	return undefined;
}

function hostMatchesAny(hosts: string[], cookieHost: string): boolean {
	const cookieDomain = cookieHost.startsWith('.') ? cookieHost.slice(1) : cookieHost;
	return hosts.some((host) => hostMatchesCookieDomain(host, cookieDomain));
}

function dedupeCookies(cookies: Cookie[]): Cookie[] {
	const merged = new Map<string, Cookie>();
	for (const cookie of cookies) {
		const key = `${cookie.name}|${cookie.domain ?? ''}|${cookie.path ?? ''}`;
		if (!merged.has(key)) merged.set(key, cookie);
	}
	return Array.from(merged.values());
}
