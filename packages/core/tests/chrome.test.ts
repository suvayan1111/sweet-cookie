import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
	secureMock: vi.fn(),
	sqliteMock: vi.fn(),
}));

vi.mock('../src/providers/chromeCookiesSecure.js', () => ({
	getCookiesFromChrome: mocks.secureMock,
}));

vi.mock('../src/providers/chromeSqliteMac.js', () => ({
	getCookiesFromChromeSqliteMac: mocks.sqliteMock,
}));

import { getCookiesFromChrome } from '../src/providers/chrome.js';

describe('chrome provider (auto)', () => {
	beforeEach(() => {
		mocks.secureMock.mockReset();
		mocks.sqliteMock.mockReset();
	});

	it('returns primary cookies when available', async () => {
		mocks.secureMock.mockResolvedValueOnce({
			cookies: [{ name: 'a', value: 'b', domain: 'example.com', path: '/' }],
			warnings: ['w1'],
		});
		mocks.sqliteMock.mockResolvedValueOnce({ cookies: [], warnings: ['w2'] });

		const res = await getCookiesFromChrome({}, ['https://example.com/'], null);

		expect(res.cookies).toHaveLength(1);
		expect(res.warnings).toEqual(['w1']);
		expect(mocks.sqliteMock).not.toHaveBeenCalled();
	});

	it('falls back when primary is empty (darwin only)', async () => {
		mocks.secureMock.mockResolvedValueOnce({ cookies: [], warnings: ['w1'] });
		mocks.sqliteMock.mockResolvedValueOnce({
			cookies: [{ name: 'a', value: 'b', domain: 'example.com', path: '/' }],
			warnings: ['w2'],
		});

		const res = await getCookiesFromChrome({}, ['https://example.com/'], null);

		if (process.platform === 'darwin') {
			expect(mocks.sqliteMock).toHaveBeenCalled();
			expect(res.cookies).toHaveLength(1);
			expect(res.warnings).toEqual(['w1', 'w2']);
		} else {
			expect(mocks.sqliteMock).not.toHaveBeenCalled();
			expect(res.cookies).toHaveLength(0);
			expect(res.warnings).toEqual(['w1']);
		}
	});
});
