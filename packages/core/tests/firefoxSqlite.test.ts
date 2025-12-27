import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import { getCookiesFromFirefox } from '../src/providers/firefoxSqlite.js';

function writeSqlite3Stub(binDir: string, stdout: string): void {
	mkdirSync(binDir, { recursive: true });

	const shim = path.join(binDir, 'sqlite3');
	const script = [
		'#!/usr/bin/env node',
		`process.stdout.write(${JSON.stringify(stdout)});`,
		'process.exit(0);',
	].join('\n');
	writeFileSync(shim, script, { encoding: 'utf8' });
	if (process.platform !== 'win32') chmodSync(shim, 0o755);

	if (process.platform === 'win32') {
		const cmd = path.join(binDir, 'sqlite3.cmd');
		writeFileSync(cmd, ['@echo off', 'node "%~dp0sqlite3" %*'].join('\r\n'), { encoding: 'utf8' });
	}
}

function writeSqlite3FailingStub(binDir: string, stderr: string): void {
	mkdirSync(binDir, { recursive: true });

	const shim = path.join(binDir, 'sqlite3');
	const script = [
		'#!/usr/bin/env node',
		`process.stderr.write(${JSON.stringify(stderr)});`,
		'process.exit(1);',
	].join('\n');
	writeFileSync(shim, script, { encoding: 'utf8' });
	if (process.platform !== 'win32') chmodSync(shim, 0o755);

	if (process.platform === 'win32') {
		const cmd = path.join(binDir, 'sqlite3.cmd');
		writeFileSync(cmd, ['@echo off', 'node "%~dp0sqlite3" %*'].join('\r\n'), { encoding: 'utf8' });
	}
}

describe('firefox sqlite provider', () => {
	it('reads sqlite output via sqlite3 CLI stub', async () => {
		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-firefox-'));
		const dbDir = path.join(dir, 'profile');
		const binDir = path.join(dir, 'bin');

		mkdirSync(dbDir, { recursive: true });
		writeFileSync(path.join(dbDir, 'cookies.sqlite'), '', 'utf8');
		writeSqlite3Stub(
			binDir,
			'sid\u001Fvalue\u001F.chatgpt.com\u001F/\u001F9999999999\u001F1\u001F1\u001F2\n'
		);

		vi.stubEnv('PATH', `${binDir}:${process.env.PATH ?? ''}`);

		const res = await getCookiesFromFirefox(
			{ profile: dbDir, includeExpired: false },
			['https://chatgpt.com/'],
			null
		);

		expect(res.cookies).toHaveLength(1);
		expect(res.cookies[0]?.name).toBe('sid');
		expect(res.cookies[0]?.secure).toBe(true);
		expect(res.cookies[0]?.httpOnly).toBe(true);
		expect(res.cookies[0]?.sameSite).toBe('Strict');
	});

	it('accepts a direct cookies.sqlite path', async () => {
		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-firefox-'));
		const dbDir = path.join(dir, 'profile');
		const binDir = path.join(dir, 'bin');
		mkdirSync(dbDir, { recursive: true });
		const dbPath = path.join(dbDir, 'cookies.sqlite');
		writeFileSync(dbPath, '', 'utf8');

		writeSqlite3Stub(
			binDir,
			'sid\u001Fvalue\u001F.chatgpt.com\u001F/\u001F9999999999\u001F1\u001F1\u001F2\n'
		);

		vi.stubEnv('PATH', `${binDir}:${process.env.PATH ?? ''}`);

		const res = await getCookiesFromFirefox(
			{ profile: dbPath, includeExpired: true },
			['https://chatgpt.com/'],
			null
		);

		expect(res.cookies).toHaveLength(1);
		expect(res.cookies[0]?.name).toBe('sid');
	});

	it('resolves profile by name from default Profiles root', async () => {
		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-firefox-'));
		const homeDir = path.join(dir, 'home');
		const profilesRoot = path.join(
			homeDir,
			'Library',
			'Application Support',
			'Firefox',
			'Profiles'
		);
		const profileName = 'abc.default-release';
		const profileDir = path.join(profilesRoot, profileName);
		const binDir = path.join(dir, 'bin');

		mkdirSync(profileDir, { recursive: true });
		writeFileSync(path.join(profileDir, 'cookies.sqlite'), '', 'utf8');
		writeSqlite3Stub(
			binDir,
			'sid\u001Fvalue\u001F.chatgpt.com\u001F/\u001F9999999999\u001F1\u001F1\u001F2\n'
		);

		vi.stubEnv('HOME', homeDir);
		vi.stubEnv('PATH', `${binDir}:${process.env.PATH ?? ''}`);

		const res = await getCookiesFromFirefox(
			{ profile: profileName, includeExpired: true },
			['https://chatgpt.com/'],
			null
		);

		expect(res.cookies).toHaveLength(1);
		expect(res.cookies[0]?.name).toBe('sid');
	});

	it('auto-picks a default-release profile when no profile is specified', async () => {
		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-firefox-'));
		const homeDir = path.join(dir, 'home');
		const profilesRoot = path.join(
			homeDir,
			'Library',
			'Application Support',
			'Firefox',
			'Profiles'
		);
		const binDir = path.join(dir, 'bin');

		const defaultRelease = path.join(profilesRoot, 'abc.default-release');
		const other = path.join(profilesRoot, 'xyz.default');
		mkdirSync(defaultRelease, { recursive: true });
		mkdirSync(other, { recursive: true });
		writeFileSync(path.join(defaultRelease, 'cookies.sqlite'), '', 'utf8');
		writeFileSync(path.join(other, 'cookies.sqlite'), '', 'utf8');

		writeSqlite3Stub(
			binDir,
			'sid\u001Fvalue\u001F.chatgpt.com\u001F/\u001F9999999999\u001F1\u001F1\u001F2\n'
		);

		vi.stubEnv('HOME', homeDir);
		vi.stubEnv('PATH', `${binDir}:${process.env.PATH ?? ''}`);

		const res = await getCookiesFromFirefox(
			{ includeExpired: true },
			['https://chatgpt.com/'],
			null
		);

		expect(res.cookies).toHaveLength(1);
	});

	it('handles unreadable profile roots gracefully', async () => {
		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-firefox-'));
		const homeDir = path.join(dir, 'home');
		const profilesRoot = path.join(
			homeDir,
			'Library',
			'Application Support',
			'Firefox',
			'Profiles'
		);

		mkdirSync(path.dirname(profilesRoot), { recursive: true });
		writeFileSync(profilesRoot, 'not a dir', 'utf8');

		vi.stubEnv('HOME', homeDir);

		const res = await getCookiesFromFirefox(
			{ includeExpired: true },
			['https://chatgpt.com/'],
			null
		);

		expect(res.cookies).toEqual([]);
		expect(res.warnings.join('\n')).toContain('Firefox cookies database not found');
	});

	it('filters by allowlist', async () => {
		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-firefox-'));
		const dbDir = path.join(dir, 'profile');
		const binDir = path.join(dir, 'bin');

		mkdirSync(dbDir, { recursive: true });
		writeFileSync(path.join(dbDir, 'cookies.sqlite'), '', 'utf8');
		writeSqlite3Stub(
			binDir,
			[
				'a\u001F1\u001F.chatgpt.com\u001F/\u001F9999999999\u001F0\u001F0\u001F0\n',
				'b\u001F2\u001F.chatgpt.com\u001F/\u001F9999999999\u001F0\u001F0\u001F0\n',
			].join('')
		);

		vi.stubEnv('PATH', `${binDir}:${process.env.PATH ?? ''}`);

		const res = await getCookiesFromFirefox(
			{ profile: dbDir, includeExpired: true },
			['https://chatgpt.com/'],
			new Set(['b'])
		);

		expect(res.cookies.map((c) => c.name)).toEqual(['b']);
	});

	it('returns a warning when the database is missing', async () => {
		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-firefox-'));

		const res = await getCookiesFromFirefox(
			{ profile: path.join(dir, 'missing-profile'), includeExpired: true },
			['https://chatgpt.com/'],
			null
		);

		expect(res.cookies).toHaveLength(0);
		expect(res.warnings.join('\n')).toContain('Firefox cookies database not found');
	});

	it('returns a warning when sqlite3 fails', async () => {
		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-firefox-'));
		const dbDir = path.join(dir, 'profile');
		const binDir = path.join(dir, 'bin');

		mkdirSync(dbDir, { recursive: true });
		writeFileSync(path.join(dbDir, 'cookies.sqlite'), '', 'utf8');
		writeSqlite3FailingStub(binDir, 'boom');

		vi.stubEnv('PATH', `${binDir}:${process.env.PATH ?? ''}`);

		const res = await getCookiesFromFirefox(
			{ profile: dbDir, includeExpired: true },
			['https://chatgpt.com/'],
			null
		);

		expect(res.cookies).toHaveLength(0);
		expect(res.warnings.join('\n')).toContain('sqlite3 failed reading Firefox cookies');
	});
});
