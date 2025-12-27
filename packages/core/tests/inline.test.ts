import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { getCookiesFromInline } from '../src/providers/inline.js';

describe('inline provider', () => {
	it('accepts { cookies } JSON and filters by host', async () => {
		const payload = {
			cookies: [
				{ name: 'sid', value: 'a', domain: 'chatgpt.com', path: '/' },
				{ name: 'sid2', value: 'b', domain: 'example.com', path: '/' },
			],
		};
		const res = await getCookiesFromInline(
			{ source: 'inline-json', payload: JSON.stringify(payload) },
			['https://chatgpt.com/'],
			null
		);
		expect(res.cookies.map((c) => c.name)).toEqual(['sid']);
	});

	it('accepts base64 payloads', async () => {
		const payload = { cookies: [{ name: 'sid', value: 'a', domain: 'chatgpt.com', path: '/' }] };
		const json = JSON.stringify(payload);
		const base64 = Buffer.from(json, 'utf8').toString('base64');

		const res = await getCookiesFromInline(
			{ source: 'inline-base64', payload: base64 },
			['https://chatgpt.com/'],
			null
		);
		expect(res.cookies).toHaveLength(1);
	});

	it('accepts file payloads and allowlists names', async () => {
		const dir = mkdtempSync(path.join(tmpdir(), 'sweet-cookie-inline-'));
		const file = path.join(dir, 'cookies.json');
		writeFileSync(
			file,
			JSON.stringify({
				cookies: [
					{ name: 'a', value: '1', domain: 'chatgpt.com', path: '/' },
					{ name: 'b', value: '2', domain: 'chatgpt.com', path: '/' },
				],
			}),
			'utf8'
		);

		const res = await getCookiesFromInline(
			{ source: 'inline-file', payload: file },
			['https://chatgpt.com/'],
			new Set(['b'])
		);
		expect(res.cookies.map((c) => c.name)).toEqual(['b']);
	});

	it('can infer domain from cookie.url', async () => {
		const payload = {
			cookies: [{ name: 'sid', value: 'a', url: 'https://chatgpt.com/', path: '/' }],
		};
		const res = await getCookiesFromInline(
			{ source: 'inline-json', payload: JSON.stringify(payload) },
			['https://chatgpt.com/'],
			null
		);
		expect(res.cookies).toHaveLength(1);
	});
});
