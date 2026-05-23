import { existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";

export interface ParsedPioliumCommandArgs {
	cwd: string;
	args: string;
	tokens: string[];
	targetCwd?: string;
	error?: string;
}

export interface ParsePioliumCommandOptions {
	defaultTarget?: string;
}

const PHASE_ARG =
	/^(?:P\d+[A-Za-z]*|Q\d+[A-Za-z]*|L\d+[A-Za-z]*|V\d+[A-Za-z]*|R\d+[A-Za-z]*|M\d+[A-Za-z]*|X\d+[A-Za-z]*)$/;

export function parsePioliumCommandArgs(
	args: string,
	baseCwd: string,
	options: ParsePioliumCommandOptions = {},
): ParsedPioliumCommandArgs {
	const tokens = tokenizeCommandArgs(args);
	const defaultTarget = readOptionValue(tokens, "--plm-dir") ?? options.defaultTarget;
	const useDefaultTarget = (): ParsedPioliumCommandArgs => {
		if (!defaultTarget) return { cwd: baseCwd, args: joinCommandArgs(tokens), tokens };
		const resolvedDefault = resolveTargetPath(defaultTarget, baseCwd);
		if (isDirectory(resolvedDefault)) {
			return {
				cwd: resolvedDefault,
				args: joinCommandArgs(tokens),
				tokens,
				targetCwd: resolvedDefault,
			};
		}
		return {
			cwd: baseCwd,
			args: joinCommandArgs(tokens),
			tokens,
			error: `${defaultTarget} is not a readable directory.`,
		};
	};
	if (tokens.length === 0) return useDefaultTarget();

	const [first, ...rest] = tokens;
	if (!first || isKnownNonPathArg(first)) return useDefaultTarget();

	const resolved = resolveTargetPath(first, baseCwd);
	if (isDirectory(resolved)) {
		return {
			cwd: resolved,
			args: joinCommandArgs(rest),
			tokens: rest,
			targetCwd: resolved,
		};
	}

	if (looksLikePath(first) || existsSync(resolved)) {
		return {
			cwd: baseCwd,
			args: joinCommandArgs(rest),
			tokens: rest,
			error: `${first} is not a readable directory.`,
		};
	}

	return useDefaultTarget();
}

export function tokenizeCommandArgs(args: string): string[] {
	const tokens: string[] = [];
	let current = "";
	let quote: "'" | '"' | undefined;
	let escaped = false;

	const push = () => {
		if (current.length > 0) {
			tokens.push(current);
			current = "";
		}
	};

	for (const char of args) {
		if (escaped) {
			current += char;
			escaped = false;
			continue;
		}
		if (char === "\\" && quote !== "'") {
			escaped = true;
			continue;
		}
		if (quote) {
			if (char === quote) quote = undefined;
			else current += char;
			continue;
		}
		if (char === "'" || char === '"') {
			quote = char;
			continue;
		}
		if (/\s/.test(char)) {
			push();
			continue;
		}
		current += char;
	}
	if (escaped) current += "\\";
	push();
	return tokens;
}

export function readOptionValue(tokens: readonly string[], name: string): string | undefined {
	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		if (token === name) return tokens[i + 1];
		if (token?.startsWith(`${name}=`)) return token.slice(name.length + 1);
	}
	return undefined;
}

export function readRepeatedOptionValues(tokens: readonly string[], name: string): string[] {
	const values: string[] = [];
	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		if (token === name) {
			const value = tokens[i + 1];
			if (value) {
				values.push(value);
				i++;
			}
		} else if (token?.startsWith(`${name}=`)) {
			values.push(token.slice(name.length + 1));
		}
	}
	return values;
}

function isKnownNonPathArg(arg: string): boolean {
	return arg.startsWith("-") || PHASE_ARG.test(arg) || /^https?:\/\//.test(arg);
}

function resolveTargetPath(input: string, baseCwd: string): string {
	const expanded =
		input === "~" ? homedir() : input.startsWith("~/") ? resolve(homedir(), input.slice(2)) : input;
	return isAbsolute(expanded) ? expanded : resolve(baseCwd, expanded);
}

function isDirectory(path: string): boolean {
	try {
		return statSync(path).isDirectory();
	} catch {
		return false;
	}
}

function looksLikePath(arg: string): boolean {
	return (
		arg === "~" ||
		arg.startsWith("~/") ||
		arg.startsWith("./") ||
		arg.startsWith("../") ||
		arg.includes("/")
	);
}

function joinCommandArgs(tokens: readonly string[]): string {
	return tokens.map(quoteCommandArg).join(" ");
}

function quoteCommandArg(token: string): string {
	if (token.length === 0) return '""';
	if (!/\s|["'\\]/.test(token)) return token;
	return `"${token.replace(/(["\\])/g, "\\$1")}"`;
}
