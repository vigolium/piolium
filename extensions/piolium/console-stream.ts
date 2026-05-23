export interface PioliumConsoleStream {
	enabled: boolean;
	writeLine(line: string): void;
	writeBlock(title: string, lines: readonly string[]): void;
}

export interface PioliumConsoleStreamOptions {
	argv?: readonly string[];
	env?: Record<string, string | undefined>;
	write?: (text: string) => void;
}

export function isPiStreamingOutputMode(argv: readonly string[] = process.argv): boolean {
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		if (arg === "--mode" && argv[i + 1] === "streaming") return true;
		if (arg === "--mode=streaming") return true;
	}
	return false;
}

function envFlagEnabled(value: string | undefined): boolean | undefined {
	if (value === undefined) return undefined;
	const normalized = value.trim().toLowerCase();
	if (["0", "false", "no", "off"].includes(normalized)) return false;
	return normalized.length > 0;
}

export function isPioliumConsoleStreamEnabled(
	argv: readonly string[] = process.argv,
	env: Record<string, string | undefined> = process.env,
): boolean {
	const envEnabled = envFlagEnabled(env.PIOLIUM_CONSOLE_STREAM);
	if (envEnabled !== undefined) return envEnabled;
	return isPiStreamingOutputMode(argv);
}

export function createPioliumConsoleStream(
	options: PioliumConsoleStreamOptions = {},
): PioliumConsoleStream {
	const enabled = isPioliumConsoleStreamEnabled(
		options.argv ?? process.argv,
		options.env ?? process.env,
	);
	const write = options.write ?? ((text: string) => process.stderr.write(text));
	return {
		enabled,
		writeLine: (line) => {
			if (enabled) write(`${line}\n`);
		},
		writeBlock: (title, lines) => {
			if (!enabled) return;
			write(`\n=== ${title} ===\n`);
			for (const line of lines) write(`${line}\n`);
		},
	};
}
