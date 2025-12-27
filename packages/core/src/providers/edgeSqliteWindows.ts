import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';

import type { GetCookiesResult } from '../types.js';
import { decryptChromiumAes256GcmCookieValue } from './chromeSqlite/crypto.js';
import { getCookiesFromChromeSqliteDb } from './chromeSqlite/shared.js';
import { dpapiUnprotect } from './chromeSqlite/windowsDpapi.js';

export async function getCookiesFromEdgeSqliteWindows(
	options: { profile?: string; includeExpired?: boolean; debug?: boolean },
	origins: string[],
	allowlistNames: Set<string> | null
): Promise<GetCookiesResult> {
	const { dbPath, userDataDir } = resolveEdgePathsWindows(options.profile);
	if (!dbPath || !userDataDir) {
		return { cookies: [], warnings: ['Edge cookies database not found.'] };
	}

	// On Windows, Edge stores an AES key in `Local State` encrypted with DPAPI (CurrentUser).
	// That master key is then used for AES-256-GCM cookie values (`v10`/`v11`/`v20` prefixes).
	const masterKey = await getWindowsEdgeMasterKey(userDataDir);
	if (!masterKey.ok) {
		return { cookies: [], warnings: [masterKey.error] };
	}

	const decrypt = (
		encryptedValue: Uint8Array,
		opts: { stripHashPrefix: boolean }
	): string | null => {
		return decryptChromiumAes256GcmCookieValue(encryptedValue, masterKey.value, {
			stripHashPrefix: opts.stripHashPrefix,
		});
	};

	const dbOptions: { dbPath: string; profile?: string; includeExpired?: boolean; debug?: boolean } =
		{
			dbPath,
		};
	if (options.profile) dbOptions.profile = options.profile;
	if (options.includeExpired !== undefined) dbOptions.includeExpired = options.includeExpired;
	if (options.debug !== undefined) dbOptions.debug = options.debug;

	return await getCookiesFromChromeSqliteDb(dbOptions, origins, allowlistNames, decrypt);
}

async function getWindowsEdgeMasterKey(
	userDataDir: string
): Promise<{ ok: true; value: Buffer } | { ok: false; error: string }> {
	const localStatePath = path.join(userDataDir, 'Local State');
	if (!existsSync(localStatePath)) {
		return { ok: false, error: 'Edge Local State file not found.' };
	}
	let encryptedKeyB64: string | null = null;
	try {
		const raw = readFileSync(localStatePath, 'utf8');
		const parsed = JSON.parse(raw) as { os_crypt?: { encrypted_key?: unknown } };
		encryptedKeyB64 =
			typeof parsed.os_crypt?.encrypted_key === 'string' ? parsed.os_crypt.encrypted_key : null;
	} catch (error) {
		return {
			ok: false,
			error: `Failed to parse Edge Local State: ${error instanceof Error ? error.message : String(error)}`,
		};
	}

	if (!encryptedKeyB64)
		return { ok: false, error: 'Edge Local State missing os_crypt.encrypted_key.' };

	let encryptedKey: Buffer;
	try {
		encryptedKey = Buffer.from(encryptedKeyB64, 'base64');
	} catch {
		return { ok: false, error: 'Edge Local State contains an invalid encrypted_key.' };
	}

	const prefix = Buffer.from('DPAPI', 'utf8');
	if (!encryptedKey.subarray(0, prefix.length).equals(prefix)) {
		return { ok: false, error: 'Edge encrypted_key does not start with DPAPI prefix.' };
	}

	const unprotected = await dpapiUnprotect(encryptedKey.subarray(prefix.length));
	if (!unprotected.ok) {
		return { ok: false, error: `DPAPI decrypt failed: ${unprotected.error}` };
	}
	return { ok: true, value: unprotected.value };
}

function resolveEdgePathsWindows(profile?: string): {
	dbPath: string | null;
	userDataDir: string | null;
} {
	// biome-ignore lint/complexity/useLiteralKeys: process.env is an index signature under strict TS.
	const localAppData = process.env['LOCALAPPDATA'];
	const root = localAppData ? path.join(localAppData, 'Microsoft', 'Edge', 'User Data') : null;

	if (profile && looksLikePath(profile)) {
		const expanded = expandPath(profile);
		const candidates = expanded.endsWith('Cookies')
			? [expanded]
			: [
					path.join(expanded, 'Network', 'Cookies'),
					path.join(expanded, 'Cookies'),
					path.join(expanded, 'Default', 'Network', 'Cookies'),
				];
		for (const candidate of candidates) {
			if (!existsSync(candidate)) continue;
			const userDataDir = findUserDataDir(candidate);
			return { dbPath: candidate, userDataDir };
		}
		if (existsSync(path.join(expanded, 'Local State'))) {
			return { dbPath: null, userDataDir: expanded };
		}
	}

	const profileDir = profile && profile.trim().length > 0 ? profile.trim() : 'Default';
	if (!root) return { dbPath: null, userDataDir: null };
	const candidates = [
		path.join(root, profileDir, 'Network', 'Cookies'),
		path.join(root, profileDir, 'Cookies'),
	];
	for (const candidate of candidates) {
		if (existsSync(candidate)) return { dbPath: candidate, userDataDir: root };
	}
	return { dbPath: null, userDataDir: root };
}

function findUserDataDir(cookiesDbPath: string): string | null {
	let current = path.dirname(cookiesDbPath);
	for (let i = 0; i < 6; i += 1) {
		const localState = path.join(current, 'Local State');
		if (existsSync(localState)) return current;
		const next = path.dirname(current);
		if (next === current) break;
		current = next;
	}
	return null;
}

function looksLikePath(value: string): boolean {
	return value.includes('/') || value.includes('\\');
}

function expandPath(input: string): string {
	if (input.startsWith('~/')) return path.join(homedir(), input.slice(2));
	return path.isAbsolute(input) ? input : path.resolve(process.cwd(), input);
}
