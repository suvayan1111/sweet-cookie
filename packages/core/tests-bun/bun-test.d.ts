declare module 'bun:test' {
	// biome-ignore lint/suspicious/noExplicitAny: bun test types are runtime-provided; keep shim tiny.
	export const expect: any;
	export function test(name: string, fn: () => void | Promise<void>): void;
	export function describe(name: string, fn: () => void): void;
}
