import type { Cookie, GetCookiesResult } from '../types.js';

import { getCookiesFromChrome as getCookiesFromChromeCookiesSecure } from './chromeCookiesSecure.js';
import { getCookiesFromChromeSqliteMac } from './chromeSqliteMac.js';

export async function getCookiesFromChrome(
	options: { profile?: string; timeoutMs?: number; includeExpired?: boolean; debug?: boolean },
	origins: string[],
	allowlistNames: Set<string> | null
): Promise<GetCookiesResult> {
	const warnings: string[] = [];

	const primary = await getCookiesFromChromeCookiesSecure(options, origins, allowlistNames);
	warnings.push(...primary.warnings);
	if (primary.cookies.length) {
		return { cookies: primary.cookies, warnings };
	}

	/* c8 ignore next */
	if (process.platform !== 'darwin') {
		return { cookies: [], warnings };
	}

	const fallbackOptions: Parameters<typeof getCookiesFromChromeSqliteMac>[0] = {};
	if (options.profile) fallbackOptions.profile = options.profile;
	if (options.includeExpired !== undefined) fallbackOptions.includeExpired = options.includeExpired;
	if (options.debug !== undefined) fallbackOptions.debug = options.debug;

	const fallback = await getCookiesFromChromeSqliteMac(fallbackOptions, origins, allowlistNames);
	warnings.push(...fallback.warnings);
	const cookies: Cookie[] = fallback.cookies;

	return { cookies, warnings };
}
