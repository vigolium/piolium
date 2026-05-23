// Hand-written shim for the bundled `yaml` package (extensions/piolium/_vendor/yaml.bundle.mjs).
// We only consume `parse` and `stringify`; everything else is intentionally
// omitted to keep the surface minimal.

export function parse(src: string, options?: unknown): unknown;
export function stringify(value: unknown, options?: { lineWidth?: number; [k: string]: unknown }): string;
