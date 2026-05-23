import { CustomEditor, type KeybindingsManager, type Theme } from "@earendil-works/pi-coding-agent";
import { type EditorTheme, type TUI, truncateToWidth, visibleWidth } from "@earendil-works/pi-tui";

export const PIOLIUM_SRCERY_THEME_NAME = "piolium-srcery";
export const PIOLIUM_PROMPT_PREFIX = "piolium-audit ▶ ";
export const PIOLIUM_PROMPT_PREFIX_GREEN = "\x1b[38;2;152;188;55m";
const RESET_FOREGROUND = "\x1b[39m";

export function shouldUsePioliumPromptPrefix(theme: Pick<Theme, "name">): boolean {
	return theme.name === PIOLIUM_SRCERY_THEME_NAME;
}

export class PioliumPromptPrefixEditor extends CustomEditor {
	private readonly prefixWidth = visibleWidth(PIOLIUM_PROMPT_PREFIX);

	constructor(tui: TUI, theme: EditorTheme, keybindings: KeybindingsManager) {
		super(tui, theme, keybindings, { paddingX: visibleWidth(PIOLIUM_PROMPT_PREFIX) });
	}

	override render(width: number): string[] {
		const lines = super.render(width);
		if (lines.length < 3) return lines;

		const renderedPrefixWidth = Math.min(this.prefixWidth, Math.max(0, Math.floor((width - 1) / 2)));
		if (renderedPrefixWidth <= 0) return lines;

		const plainPrefix = truncateToWidth(PIOLIUM_PROMPT_PREFIX, renderedPrefixWidth, "");
		if (!plainPrefix) return lines;

		const expectedPadding = " ".repeat(renderedPrefixWidth);
		const promptLine = lines[1] ?? "";
		const styledPrefix = `${PIOLIUM_PROMPT_PREFIX_GREEN}${plainPrefix}${RESET_FOREGROUND}`;
		lines[1] = promptLine.startsWith(expectedPadding)
			? `${styledPrefix}${promptLine.slice(renderedPrefixWidth)}`
			: truncateToWidth(`${styledPrefix}${promptLine}`, width);

		return lines;
	}
}
