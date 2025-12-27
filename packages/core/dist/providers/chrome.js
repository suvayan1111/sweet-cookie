import { getCookiesFromChrome as getCookiesFromChromeCookiesSecure } from './chromeCookiesSecure.js';
import { getCookiesFromChromeSqliteMac } from './chromeSqliteMac.js';
export async function getCookiesFromChrome(options, origins, allowlistNames) {
    const warnings = [];
    const primary = await getCookiesFromChromeCookiesSecure(options, origins, allowlistNames);
    warnings.push(...primary.warnings);
    if (primary.cookies.length) {
        return { cookies: primary.cookies, warnings };
    }
    /* c8 ignore next */
    if (process.platform !== 'darwin') {
        return { cookies: [], warnings };
    }
    const fallbackOptions = {};
    if (options.profile)
        fallbackOptions.profile = options.profile;
    if (options.includeExpired !== undefined)
        fallbackOptions.includeExpired = options.includeExpired;
    if (options.debug !== undefined)
        fallbackOptions.debug = options.debug;
    const fallback = await getCookiesFromChromeSqliteMac(fallbackOptions, origins, allowlistNames);
    warnings.push(...fallback.warnings);
    const cookies = fallback.cookies;
    return { cookies, warnings };
}
//# sourceMappingURL=chrome.js.map