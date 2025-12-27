import { createDecipheriv, pbkdf2Sync } from 'node:crypto';

const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

export function deriveAes128CbcKeyFromPassword(
	password: string,
	options: { iterations: number }
): Buffer {
	return pbkdf2Sync(password, 'saltysalt', options.iterations, 16, 'sha1');
}

export function decryptChromiumAes128CbcCookieValue(
	encryptedValue: Uint8Array,
	keyCandidates: readonly Buffer[],
	options: { stripHashPrefix: boolean; treatUnknownPrefixAsPlaintext?: boolean }
): string | null {
	const buf = Buffer.from(encryptedValue);
	if (buf.length < 3) return null;

	const prefix = buf.subarray(0, 3).toString('utf8');
	const hasVersionPrefix = /^v\d\d$/.test(prefix);

	if (!hasVersionPrefix) {
		if (options.treatUnknownPrefixAsPlaintext === false) return null;
		return decodeCookieValueBytes(buf, false);
	}

	const ciphertext = buf.subarray(3);
	if (!ciphertext.length) return '';

	for (const key of keyCandidates) {
		const decrypted = tryDecryptAes128Cbc(ciphertext, key);
		if (!decrypted) continue;
		const decoded = decodeCookieValueBytes(decrypted, options.stripHashPrefix);
		if (decoded !== null) return decoded;
	}

	return null;
}

export function decryptChromiumAes256GcmCookieValue(
	encryptedValue: Uint8Array,
	key: Buffer,
	options: { stripHashPrefix: boolean }
): string | null {
	const buf = Buffer.from(encryptedValue);
	if (buf.length < 3) return null;
	const prefix = buf.subarray(0, 3).toString('utf8');
	if (!/^v\d\d$/.test(prefix)) return null;

	const payload = buf.subarray(3);
	if (payload.length < 12 + 16) return null;

	const nonce = payload.subarray(0, 12);
	const authenticationTag = payload.subarray(payload.length - 16);
	const ciphertext = payload.subarray(12, payload.length - 16);

	try {
		const decipher = createDecipheriv('aes-256-gcm', key, nonce);
		decipher.setAuthTag(authenticationTag);
		const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
		return decodeCookieValueBytes(plaintext, options.stripHashPrefix);
	} catch {
		return null;
	}
}

function tryDecryptAes128Cbc(ciphertext: Buffer, key: Buffer): Buffer | null {
	try {
		const iv = Buffer.alloc(16, 0x20);
		const decipher = createDecipheriv('aes-128-cbc', key, iv);
		decipher.setAutoPadding(false);
		const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
		return removePkcs7Padding(plaintext);
	} catch {
		return null;
	}
}

function removePkcs7Padding(value: Buffer): Buffer {
	if (!value.length) return value;
	const padding = value[value.length - 1];
	if (!padding || padding > 16) return value;
	return value.subarray(0, value.length - padding);
}

function decodeCookieValueBytes(value: Buffer, stripHashPrefix: boolean): string | null {
	const bytes = stripHashPrefix && value.length >= 32 ? value.subarray(32) : value;
	try {
		return stripLeadingControlChars(UTF8_DECODER.decode(bytes));
	} catch {
		return null;
	}
}

function stripLeadingControlChars(value: string): string {
	let i = 0;
	while (i < value.length && value.charCodeAt(i) < 0x20) i += 1;
	return value.slice(i);
}
