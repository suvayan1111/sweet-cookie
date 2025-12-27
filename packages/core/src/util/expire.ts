export function normalizeExpiration(expires?: number): number | undefined {
	if (!expires || Number.isNaN(expires)) return undefined;
	const value = Number(expires);
	if (value <= 0) return undefined;

	// Chromium can use microseconds since 1601 (Windows epoch) in sqlite stores.
	if (value > 10_000_000_000_000) {
		return Math.round(value / 1_000_000 - 11_644_473_600);
	}

	// milliseconds epoch
	// (seconds epoch is already ~1.7e9, so the cutoff must be much higher than 1e9)
	if (value > 10_000_000_000) {
		return Math.round(value / 1000);
	}

	// seconds epoch
	return Math.round(value);
}
