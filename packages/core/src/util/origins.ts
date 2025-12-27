export function normalizeOrigins(url: string, extraOrigins?: string[]): string[] {
	const origins: string[] = [];
	try {
		const parsed = new URL(url);
		origins.push(ensureTrailingSlash(parsed.origin));
	} catch {
		// ignore
	}

	for (const raw of extraOrigins ?? []) {
		const trimmed = raw.trim();
		if (!trimmed) continue;
		try {
			const parsed = new URL(trimmed);
			origins.push(ensureTrailingSlash(parsed.origin));
		} catch {
			// ignore malformed extras
		}
	}

	return Array.from(new Set(origins));
}

function ensureTrailingSlash(origin: string): string {
	return origin.endsWith('/') ? origin : `${origin}/`;
}
