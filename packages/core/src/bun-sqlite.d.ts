declare module 'bun:sqlite' {
	export type BunSqliteDatabaseOptions = {
		readonly?: boolean;
	};

	export class Database {
		constructor(filename: string, options?: BunSqliteDatabaseOptions);
		close(): void;
		query<T = unknown>(sql: string): { all: () => T[]; run: () => unknown };
	}
}
