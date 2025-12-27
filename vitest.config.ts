import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		environment: 'node',
		poolOptions: {
			threads: {
				minThreads: 1,
				maxThreads: 1,
			},
		},
		include: ['packages/**/tests/**/*.test.ts'],
		exclude: ['**/dist/**', '**/node_modules/**', '**/coverage/**'],
		coverage: {
			provider: 'v8',
			all: true,
			include: ['packages/core/src/**/*.ts'],
			exclude: ['**/*.d.ts', '**/dist/**', '**/node_modules/**', '**/tests/**'],
			thresholds: {
				branches: 70,
				functions: 70,
				lines: 70,
				statements: 70,
			},
		},
	},
});
