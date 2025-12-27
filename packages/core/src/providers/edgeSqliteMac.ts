import { existsSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';

import type { GetCookiesResult } from '../types.js';
import { execCapture } from '../util/exec.js';
import {
	decryptChromiumAes128CbcCookieValue,
	deriveAes128CbcKeyFromPassword,
} from './chromeSqlite/crypto.js';
import { getCookiesFromChromeSqliteDb } from './chromeSqlite/shared.js';

export async function getCookiesFromEdgeSqliteMac(
	options: { profile?: string; includeExpired?: boolean; debug?: boolean; timeoutMs?: number },
	origins: string[],
	allowlistNames: Set<string> | null
): Promise<GetCookiesResult> {
	const dbPath = resolveEdgeCookiesDb(options.profile);
	if (!dbPath) {
		return { cookies: [], warnings: ['Edge cookies database not found.'] };
	}

	const warnings: string[] = [];

	// On macOS, Edge stores its "Safe Storage" secret in Keychain (same scheme as Chrome).
	// `security find-generic-password` is stable and avoids any native Node keychain modules.
	const passwordResult = await readEdgeSafeStoragePassword(options.timeoutMs ?? 3_000);
	if (!passwordResult.ok) {
		warnings.push(passwordResult.error);
		return { cookies: [], warnings };
	}

	const edgePassword = passwordResult.value.trim();
	if (!edgePassword) {
		warnings.push('macOS Keychain returned an empty Microsoft Edge Safe Storage password.');
		return { cookies: [], warnings };
	}

	// Chromium uses PBKDF2(password, "saltysalt", 1003, 16, sha1) for AES-128-CBC cookie values on macOS.
	const key = deriveAes128CbcKeyFromPassword(edgePassword, { iterations: 1003 });
	const decrypt = (encryptedValue: Uint8Array, opts: { stripHashPrefix: boolean }): string | null =>
		decryptChromiumAes128CbcCookieValue(encryptedValue, [key], {
			stripHashPrefix: opts.stripHashPrefix,
			treatUnknownPrefixAsPlaintext: true,
		});

	const dbOptions: { dbPath: string; profile?: string; includeExpired?: boolean; debug?: boolean } =
		{
			dbPath,
		};
	if (options.profile) dbOptions.profile = options.profile;
	if (options.includeExpired !== undefined) dbOptions.includeExpired = options.includeExpired;
	if (options.debug !== undefined) dbOptions.debug = options.debug;

	const result = await getCookiesFromChromeSqliteDb(dbOptions, origins, allowlistNames, decrypt);
	result.warnings.unshift(...warnings);
	return result;
}

async function readEdgeSafeStoragePassword(
	timeoutMs: number
): Promise<{ ok: true; value: string } | { ok: false; error: string }> {
	// Primary: stable Edge keychain item name.
	const attempts: Array<{ account: string; service: string }> = [
		{ account: 'Microsoft Edge', service: 'Microsoft Edge Safe Storage' },
		// Some setups use different account/service labels. Keep a small fallback list.
		{ account: 'Microsoft Edge', service: 'Microsoft Edge' },
	];

	for (const attempt of attempts) {
		const res = await execCapture(
			'security',
			['find-generic-password', '-w', '-a', attempt.account, '-s', attempt.service],
			{ timeoutMs }
		);
		if (res.code === 0) return { ok: true, value: res.stdout };
	}

	return {
		ok: false,
		error:
			'Failed to read macOS Keychain (Microsoft Edge Safe Storage): ' +
			'permission denied / keychain locked / entry missing.',
	};
}

function resolveEdgeCookiesDb(profile?: string): string | null {
	const home = homedir();
	/* c8 ignore next */
	const roots =
		process.platform === 'darwin'
			? [path.join(home, 'Library', 'Application Support', 'Microsoft Edge')]
			: [];

	const candidates: string[] = [];

	if (profile && looksLikePath(profile)) {
		const expanded = expandPath(profile);
		const stat = safeStat(expanded);
		if (stat?.isFile()) return expanded;
		candidates.push(path.join(expanded, 'Cookies'));
		candidates.push(path.join(expanded, 'Network', 'Cookies'));
	} else {
		const profileDir = profile && profile.trim().length > 0 ? profile.trim() : 'Default';
		for (const root of roots) {
			candidates.push(path.join(root, profileDir, 'Cookies'));
			candidates.push(path.join(root, profileDir, 'Network', 'Cookies'));
		}
	}

	for (const candidate of candidates) {
		if (existsSync(candidate)) return candidate;
	}

	return null;
}

function safeStat(candidate: string): { isFile: () => boolean; isDirectory: () => boolean } | null {
	try {
		return statSync(candidate);
	} catch {
		return null;
	}
}

function expandPath(input: string): string {
	if (input.startsWith('~/')) return path.join(homedir(), input.slice(2));
	return path.isAbsolute(input) ? input : path.resolve(process.cwd(), input);
}

function looksLikePath(value: string): boolean {
	return value.includes('/') || value.includes('\\');
}
