import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';

import type { Cookie, CookieSameSite, GetCookiesResult } from '../types.js';
import { execCapture } from '../util/exec.js';
import { hostMatchesCookieDomain } from '../util/hostMatch.js';

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

	const cookies: Cookie[] = [];
	const lines = result.stdout.split('\n').map((l) => l.trimEnd());
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

	return { cookies: dedupeCookies(cookies), warnings };
}

function resolveFirefoxCookiesDb(profile?: string): string | null {
	const home = homedir();
	// biome-ignore lint/complexity/useLiteralKeys: process.env is an index signature under strict TS.
	const appData = process.env['APPDATA'];
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
