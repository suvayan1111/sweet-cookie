export type BrowserName = 'chrome' | 'firefox' | 'safari';

export type CookieSameSite = 'Strict' | 'Lax' | 'None';

export interface Cookie {
	name: string;
	value: string;
	domain?: string;
	path?: string;
	url?: string;
	expires?: number;
	secure?: boolean;
	httpOnly?: boolean;
	sameSite?: CookieSameSite;
	source?: {
		browser: BrowserName;
		profile?: string;
		origin?: string;
		storeId?: string;
	};
}

export type CookieMode = 'merge' | 'first';

export interface GetCookiesOptions {
	url: string;
	origins?: string[];
	names?: string[];
	browsers?: BrowserName[];
	/** Alias for chromeProfile (common case). */
	profile?: string;
	chromeProfile?: string;
	firefoxProfile?: string;
	/** Override path to Safari Cookies.binarycookies (for tests / debugging). */
	safariCookiesFile?: string;
	includeExpired?: boolean;
	timeoutMs?: number;
	debug?: boolean;
	mode?: CookieMode;
	inlineCookiesFile?: string;
	inlineCookiesJson?: string;
	inlineCookiesBase64?: string;
	/** If true, also tries ~/.oracle/cookies.{json,base64} as inline sources. */
	oracleInlineFallback?: boolean;
}

export interface GetCookiesResult {
	cookies: Cookie[];
	warnings: string[];
}

export interface CookieHeaderOptions {
	dedupeByName?: boolean;
	sort?: 'name' | 'none';
}
