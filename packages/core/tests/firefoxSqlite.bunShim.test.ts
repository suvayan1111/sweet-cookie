import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it, vi } from 'vitest';

vi.mock('bun:sqlite', () => {
	class Database {
		query() {
			return {
				all: () => [
					{
						name: 'sid',
						value: 'value',
						host: '.chatgpt.com',
						path: '/',
						expiry: 9999999999,
						isSecure: 1,
						isHttpOnly: 1,
						sameSite: 2,
					},
				],
			};
		}
		close() {}
	}

	return { Database };
});

import { getCookiesFromFirefox } from '../src/providers/firefoxSqlite.js';

describe('firefox sqlite provider (bun shim)', () => {
	it('uses bun:sqlite when bun runtime detected', async () => {
		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-firefox-bun-'));
		const dbDir = path.join(dir, 'profile');
		mkdirSync(dbDir, { recursive: true });
		writeFileSync(path.join(dbDir, 'cookies.sqlite'), '', { encoding: 'utf8' });

		const prev = (process.versions as unknown as { bun?: string }).bun;
		(process.versions as unknown as { bun?: string }).bun = '1.0.0';
		try {
			const res = await getCookiesFromFirefox(
				{ profile: dbDir, includeExpired: false },
				['https://chatgpt.com/'],
				null
			);

			expect(res.cookies).toHaveLength(1);
			expect(res.cookies[0]?.sameSite).toBe('Strict');
		} finally {
			(process.versions as unknown as { bun?: string }).bun = prev;
		}
	});
});
