import { visibleWidth } from "@earendil-works/pi-tui";
import { describe, expect, it } from "vitest";
import {
	PIOLIUM_PROMPT_PREFIX,
	PIOLIUM_PROMPT_PREFIX_GREEN,
	PioliumPromptPrefixEditor,
	shouldUsePioliumPromptPrefix,
} from "../extensions/piolium/prompt-prefix-editor.ts";

const tui = {
	terminal: { rows: 40 },
	requestRender: () => {},
} as never;

const editorTheme = {
	borderColor: (text: string) => text,
	selectList: {},
} as never;

const keybindings = {
	matches: () => false,
} as never;

const ANSI_ESCAPE = String.fromCharCode(27);
const ANSI_PATTERN = new RegExp(`${ANSI_ESCAPE}\\[[0-9;]*m`, "g");
const stripAnsi = (text: string) => text.replace(ANSI_PATTERN, "");

describe("piolium prompt prefix editor", () => {
	it("only activates for the bundled Srcery theme", () => {
		expect(shouldUsePioliumPromptPrefix({ name: "piolium-srcery" })).toBe(true);
		expect(shouldUsePioliumPromptPrefix({ name: "dark" })).toBe(false);
	});

	it("renders the Piolium prefix on the first prompt line", () => {
		const editor = new PioliumPromptPrefixEditor(tui, editorTheme, keybindings);
		editor.setText("run audit");

		const lines = editor.render(60);

		expect(lines[1]).toContain(PIOLIUM_PROMPT_PREFIX_GREEN);
		expect(stripAnsi(lines[1] ?? "")).toContain(`${PIOLIUM_PROMPT_PREFIX}run audit`);
		expect(lines.every((line) => visibleWidth(line) <= 60)).toBe(true);
	});
});
