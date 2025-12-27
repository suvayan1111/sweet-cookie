import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
	macMock: vi.fn(),
	linuxMock: vi.fn(),
	windowsMock: vi.fn(),
}));

vi.mock('../src/providers/chromeSqliteMac.js', () => ({
	getCookiesFromChromeSqliteMac: mocks.macMock,
}));

vi.mock('../src/providers/chromeSqliteLinux.js', () => ({
	getCookiesFromChromeSqliteLinux: mocks.linuxMock,
}));

vi.mock('../src/providers/chromeSqliteWindows.js', () => ({
	getCookiesFromChromeSqliteWindows: mocks.windowsMock,
}));

import { getCookiesFromChrome } from '../src/providers/chrome.js';

describe('chrome provider (auto)', () => {
	beforeEach(() => {
		mocks.macMock.mockReset();
		mocks.linuxMock.mockReset();
		mocks.windowsMock.mockReset();
	});

	it('delegates to the platform provider', async () => {
		mocks.macMock.mockResolvedValueOnce({
			cookies: [{ name: 'a', value: 'b', domain: 'example.com', path: '/' }],
			warnings: ['w-mac'],
		});
		mocks.linuxMock.mockResolvedValueOnce({
			cookies: [{ name: 'a', value: 'b', domain: 'example.com', path: '/' }],
			warnings: ['w-linux'],
		});
		mocks.windowsMock.mockResolvedValueOnce({
			cookies: [{ name: 'a', value: 'b', domain: 'example.com', path: '/' }],
			warnings: ['w-win'],
		});

		const res = await getCookiesFromChrome({}, ['https://example.com/'], null);

		expect(res.cookies).toHaveLength(1);
		if (process.platform === 'darwin') {
			expect(mocks.macMock).toHaveBeenCalled();
			expect(res.warnings).toEqual(['w-mac']);
		} else if (process.platform === 'linux') {
			expect(mocks.linuxMock).toHaveBeenCalled();
			expect(res.warnings).toEqual(['w-linux']);
		} else if (process.platform === 'win32') {
			expect(mocks.windowsMock).toHaveBeenCalled();
			expect(res.warnings).toEqual(['w-win']);
		} else {
			expect(res.cookies).toHaveLength(0);
		}
	});
});
