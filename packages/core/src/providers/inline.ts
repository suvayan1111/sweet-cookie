import type { Cookie, GetCookiesResult } from '../types.js';
import { tryDecodeBase64Json } from '../util/base64.js';
import { readTextFileIfExists } from '../util/fs.js';
import { hostMatchesCookieDomain } from '../util/hostMatch.js';

type InlineSource = { source: string; payload: string };

export async function getCookiesFromInline(
	inline: InlineSource,
	origins: string[],
	allowlistNames: Set<string> | null
): Promise<GetCookiesResult> {
	const warnings: string[] = [];

	const rawPayload =
		inline.source.endsWith('file') ||
		inline.payload.endsWith('.json') ||
		inline.payload.endsWith('.base64')
			? ((await readTextFileIfExists(inline.payload)) ?? inline.payload)
			: inline.payload;

	const decoded = tryDecodeBase64Json(rawPayload) ?? rawPayload;
	const parsed = tryParseCookiePayload(decoded);
	if (!parsed) {
		return { cookies: [], warnings };
	}

	const hostAllow = new Set(origins.map((o) => new URL(o).hostname));

	const cookies: Cookie[] = [];
	for (const cookie of parsed.cookies) {
		if (!cookie?.name) continue;
		if (allowlistNames && allowlistNames.size > 0 && !allowlistNames.has(cookie.name)) continue;
		const domain = cookie.domain ?? (cookie.url ? safeHostnameFromUrl(cookie.url) : undefined);
		if (domain && hostAllow.size > 0 && !matchesAnyHost(hostAllow, domain)) continue;
		cookies.push(cookie);
	}

	return { cookies, warnings };
}

function tryParseCookiePayload(input: string): { cookies: Cookie[] } | null {
	const trimmed = input.trim();
	if (!trimmed) return null;
	try {
		const parsed = JSON.parse(trimmed) as unknown;
		if (Array.isArray(parsed)) {
			return { cookies: parsed as Cookie[] };
		}
		if (
			parsed &&
			typeof parsed === 'object' &&
			Array.isArray((parsed as { cookies?: unknown }).cookies)
		) {
			return { cookies: (parsed as { cookies: Cookie[] }).cookies };
		}
		return null;
	} catch {
		return null;
	}
}

function matchesAnyHost(hosts: Set<string>, cookieDomain: string): boolean {
	for (const host of hosts) {
		if (hostMatchesCookieDomain(host, cookieDomain)) return true;
	}
	return false;
}

function safeHostnameFromUrl(url: string): string | undefined {
	try {
		return new URL(url).hostname;
	} catch {
		return undefined;
	}
}
