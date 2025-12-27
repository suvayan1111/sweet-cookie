import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = new URL('../dist/', import.meta.url);

await fs.mkdir(dist, { recursive: true });

await copyFile(
	new URL('../manifest.json', import.meta.url),
	new URL('../dist/manifest.json', import.meta.url)
);
await copyFile(
	new URL('../src/popup.html', import.meta.url),
	new URL('../dist/popup.html', import.meta.url)
);
await copyFile(
	new URL('../src/popup.css', import.meta.url),
	new URL('../dist/popup.css', import.meta.url)
);

async function copyFile(from, to) {
	const toPath = fileURLToPath(to);
	await fs.mkdir(path.dirname(toPath), { recursive: true });
	await fs.copyFile(fileURLToPath(from), toPath);
}
