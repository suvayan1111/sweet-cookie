import { spawn } from 'node:child_process';

export async function execCapture(
	file: string,
	args: string[],
	options: { timeoutMs?: number } = {}
): Promise<{ code: number; stdout: string; stderr: string }> {
	const timeoutMs = options.timeoutMs ?? 10_000;
	return new Promise((resolve) => {
		const child = spawn(file, args, { stdio: ['ignore', 'pipe', 'pipe'] });
		let stdout = '';
		let stderr = '';
		child.stdout.setEncoding('utf8');
		child.stderr.setEncoding('utf8');
		child.stdout.on('data', (chunk) => {
			stdout += chunk;
		});
		child.stderr.on('data', (chunk) => {
			stderr += chunk;
		});

		const timer = setTimeout(() => {
			try {
				child.kill('SIGKILL');
			} catch {
				// ignore
			}
			resolve({ code: 124, stdout, stderr: `${stderr}\nTimed out after ${timeoutMs}ms` });
		}, timeoutMs);
		timer.unref?.();

		child.on('close', (code) => {
			clearTimeout(timer);
			resolve({ code: code ?? 0, stdout, stderr });
		});
	});
}
