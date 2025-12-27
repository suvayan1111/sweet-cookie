import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it, vi } from 'vitest';

const itIfDarwin = process.platform === 'darwin' ? it : it.skip;

function buildInlinePayload(): string {
	return JSON.stringify({
		cookies: [{ name: 'inline', value: '1', domain: 'chatgpt.com', path: '/' }],
	});
}

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
		writeFileSync(cmd, ['@echo off', 'node "%~dp0sqlite3" %*'].join('\r\n'), {
			encoding: 'utf8',
		});
	}
}

describe('public API', () => {
	it('returns inline cookies first (and filters by name)', async () => {
		const { getCookies } = await import('../src/index.js');
		const res = await getCookies({
			url: 'https://chatgpt.com/',
			names: ['inline'],
			inlineCookiesJson: buildInlinePayload(),
			browsers: ['chrome', 'firefox', 'safari'],
		});
		expect(res.cookies.map((c) => c.name)).toEqual(['inline']);
	});

	it('respects SWEET_COOKIE_BROWSERS env when browsers are not provided', async () => {
		vi.resetModules();

		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-public-env-'));
		const binDir = path.join(dir, 'bin');
		const firefoxDir = path.join(dir, 'ff');
		mkdirSync(firefoxDir, { recursive: true });
		writeFileSync(path.join(firefoxDir, 'cookies.sqlite'), '', 'utf8');

		writeSqlite3Stub(
			binDir,
			'firefox\u001Ff\u001F.chatgpt.com\u001F/\u001F9999999999\u001F0\u001F0\u001F0\n'
		);
		vi.stubEnv('PATH', `${binDir}:${process.env.PATH ?? ''}`);

		const getCookiesPromised = vi.fn(async () => [
			{ name: 'chrome', value: 'c', domain: 'chatgpt.com', path: '/', secure: true },
		]);
		vi.doMock('chrome-cookies-secure', () => ({ default: { getCookiesPromised } }));

		vi.stubEnv('SWEET_COOKIE_BROWSERS', 'firefox, chrome');
		vi.stubEnv('SWEET_COOKIE_MODE', 'merge');

		const { getCookies } = await import('../src/index.js');
		const res = await getCookies({
			url: 'https://chatgpt.com/',
			firefoxProfile: firefoxDir,
			includeExpired: true,
		});

		expect(res.cookies.map((c) => c.name).sort()).toEqual(['chrome', 'firefox']);
	});

	it('ignores unknown tokens in SWEET_COOKIE_BROWSERS and invalid SWEET_COOKIE_MODE', async () => {
		vi.resetModules();

		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-public-env-'));
		const binDir = path.join(dir, 'bin');
		const firefoxDir = path.join(dir, 'ff');
		mkdirSync(firefoxDir, { recursive: true });
		writeFileSync(path.join(firefoxDir, 'cookies.sqlite'), '', 'utf8');

		writeSqlite3Stub(
			binDir,
			'firefox\u001Ff\u001F.chatgpt.com\u001F/\u001F9999999999\u001F0\u001F0\u001F0\n'
		);
		vi.stubEnv('PATH', `${binDir}:${process.env.PATH ?? ''}`);

		vi.stubEnv('SWEET_COOKIE_BROWSERS', 'firefox, nope');
		vi.stubEnv('SWEET_COOKIE_MODE', 'nope');

		const { getCookies } = await import('../src/index.js');
		const res = await getCookies({
			url: 'https://chatgpt.com/',
			firefoxProfile: firefoxDir,
			includeExpired: true,
		});

		expect(res.cookies.map((c) => c.name)).toEqual(['firefox']);
	});

	itIfDarwin('merges browser sources and dedupes by name+domain+path', async () => {
		vi.resetModules();

		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-public-'));

		const binDir = path.join(dir, 'bin');
		const firefoxDir = path.join(dir, 'ff');
		mkdirSync(firefoxDir, { recursive: true });
		writeFileSync(path.join(firefoxDir, 'cookies.sqlite'), '', 'utf8');
		writeSqlite3Stub(
			binDir,
			[
				'dup\u001Fx\u001F.chatgpt.com\u001F/\u001F9999999999\u001F0\u001F0\u001F0\n',
				'firefox\u001Ff\u001F.chatgpt.com\u001F/\u001F9999999999\u001F0\u001F0\u001F0\n',
			].join('')
		);
		vi.stubEnv('PATH', `${binDir}:${process.env.PATH ?? ''}`);

		const getCookiesPromised = vi.fn(async () => [
			{ name: 'dup', value: 'x', domain: 'chatgpt.com', path: '/', secure: true },
			{ name: 'chrome', value: 'c', domain: 'chatgpt.com', path: '/', secure: true },
		]);
		vi.doMock('chrome-cookies-secure', () => ({ default: { getCookiesPromised } }));

		const { getCookies } = await import('../src/index.js');
		const res = await getCookies({
			url: 'https://chatgpt.com/',
			browsers: ['chrome', 'firefox'],
			firefoxProfile: firefoxDir,
			includeExpired: true,
		});

		expect(res.cookies.map((c) => c.name).sort()).toEqual(['chrome', 'dup', 'firefox']);
	});

	it('mode=first returns the first non-empty browser result', async () => {
		vi.resetModules();

		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-public-first-'));
		const binDir = path.join(dir, 'bin');
		const firefoxDir = path.join(dir, 'ff');
		mkdirSync(firefoxDir, { recursive: true });
		writeFileSync(path.join(firefoxDir, 'cookies.sqlite'), '', 'utf8');

		writeSqlite3Stub(
			binDir,
			'only\u001Ff\u001F.chatgpt.com\u001F/\u001F9999999999\u001F0\u001F0\u001F0\n'
		);
		vi.stubEnv('PATH', `${binDir}:${process.env.PATH ?? ''}`);

		const getCookiesPromised = vi.fn(async () => [
			{ name: 'chrome', value: 'c', domain: 'chatgpt.com', path: '/', secure: true },
		]);
		vi.doMock('chrome-cookies-secure', () => ({ default: { getCookiesPromised } }));

		const { getCookies } = await import('../src/index.js');
		const res = await getCookies({
			url: 'https://chatgpt.com/',
			mode: 'first',
			browsers: ['firefox', 'chrome'],
			firefoxProfile: firefoxDir,
			includeExpired: true,
		});

		expect(res.cookies.map((c) => c.name)).toEqual(['only']);
	});

	it('toCookieHeader() sorts and can dedupe by name', async () => {
		const { toCookieHeader } = await import('../src/index.js');
		const header = toCookieHeader(
			[
				{ name: 'b', value: '2' },
				{ name: 'a', value: '1' },
				{ name: 'a', value: 'ignored' },
			],
			{ dedupeByName: true }
		);
		expect(header).toBe('a=1; b=2');
	});

	it('toCookieHeader() can preserve order', async () => {
		const { toCookieHeader } = await import('../src/index.js');
		const header = toCookieHeader(
			[
				{ name: 'b', value: '2' },
				{ name: 'a', value: '1' },
			],
			{ sort: 'none' }
		);
		expect(header).toBe('b=2; a=1');
	});
});
