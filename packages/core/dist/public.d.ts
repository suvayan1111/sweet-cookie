import type { Cookie, CookieHeaderOptions, GetCookiesOptions, GetCookiesResult } from './types.js';
export declare function getCookies(options: GetCookiesOptions): Promise<GetCookiesResult>;
export declare function toCookieHeader(cookies: readonly Cookie[], options?: CookieHeaderOptions): string;
//# sourceMappingURL=public.d.ts.map