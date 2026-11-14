---
name: OmaDeck
description: The project site as an Omarchy desktop you scroll through, in Tokyo Night.
colors:
  ground: "#1a1b26"
  tile: "#1f2335"
  raised: "#24283b"
  edge: "#3b4261"
  edge-dim: "#2e3350"
  term-ground: "#16161e"
  media-ground: "#0e0f15"
  selection: "#33467c"
  bright: "#ffffff"
  ink: "#c0caf5"
  quiet: "#a9b1d6"
  label: "#9aa2cc"
  blue: "#7aa2f7"
  purple: "#bb9af7"
  cyan: "#7dcfff"
  green: "#9ece6a"
  amber: "#e0af68"
  amber-hover: "#f0c27f"
typography:
  display:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "clamp(42px, min(6.6vw, 10.5svh), 96px)"
    fontWeight: 800
    lineHeight: 0.98
    letterSpacing: "-0.04em"
  headline:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "clamp(30px, 4vw, 56px)"
    fontWeight: 800
    lineHeight: 1.02
    letterSpacing: "-0.04em"
  title:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "18px"
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: "-0.02em"
  lede:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "clamp(18px, 1.6vw, 21px)"
    fontWeight: 400
    lineHeight: 1.6
  body:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: 1.6
  body-small:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.6
  code:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.6
  log:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
  bar:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "13px"
    fontWeight: 500
    lineHeight: 1
  label:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "12px"
    fontWeight: 500
    lineHeight: 1
rounded:
  none: "0px"
  ws-btn: "4px"
  logo-bar: "5px"
  logo: "12px"
spacing:
  gap-in: "6px"
  gap-out: "10px"
  gap-out-phone: "6px"
  bar: "34px"
  title-strip: "8px 12px"
  tile-pad: "clamp(20px, 3.4vw, 48px)"
  workspace-gap: "40px"
components:
  bar:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.quiet}"
    typography: "{typography.bar}"
    height: "34px"
    padding: "0 10px"
  ws-btn:
    textColor: "{colors.label}"
    typography: "{typography.bar}"
    rounded: "{rounded.ws-btn}"
    height: "24px"
    padding: "0 6px"
  ws-btn-hover:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.ink}"
  ws-btn-current:
    backgroundColor: "{colors.blue}"
    textColor: "{colors.ground}"
  tile:
    backgroundColor: "{colors.tile}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
  tile-title:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.label}"
    typography: "{typography.label}"
    padding: "8px 12px"
  terminal:
    backgroundColor: "{colors.term-ground}"
    textColor: "{colors.ink}"
    typography: "{typography.code}"
    rounded: "{rounded.none}"
    padding: "18px 16px"
  button-copy:
    backgroundColor: "{colors.blue}"
    textColor: "{colors.ground}"
    rounded: "{rounded.none}"
    padding: "0 22px"
  button-copy-hover:
    backgroundColor: "{colors.cyan}"
    textColor: "{colors.ground}"
  button-copy-active:
    backgroundColor: "{colors.purple}"
    textColor: "{colors.ground}"
  button-star:
    backgroundColor: "{colors.amber}"
    textColor: "{colors.ground}"
    rounded: "{rounded.none}"
    padding: "16px 22px"
  button-star-hover:
    backgroundColor: "{colors.amber-hover}"
    textColor: "{colors.ground}"
  step-number:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.bright}"
    size: "34px"
    rounded: "{rounded.none}"
---

# Design System: OmaDeck

## Overview

**Creative North Star: "The Desktop You Scroll Through"**

The OmaDeck site is an Omarchy screen, not a web page about one. A Waybar-style bar runs across the top; its workspaces 1 to 5 are the navigation and light up as each section scrolls into view. Every section is a workspace and every block of content is a Hyprland tile: square, 2px bordered, separated by the compositor's gaps, with a thin title strip on top. The tile under the pointer (or nearest the middle of the screen on touch) carries the lit blue-to-purple active border; the rest dim their title strips and media.

The palette is Tokyo Night, Omarchy's default theme, used as the theme itself rather than as inspiration. Hierarchy comes from scale alone: one huge JetBrains Mono ExtraBold headline per workspace, prose in the system sans, and everything else (bar, titles, code, logs, facts) in mono at small sizes. Density is a working desktop's: tight gaps, many tiles, real footage filling most of them.

Motion is the desktop's own: tiles in the first workspace open like Hyprland windows, focus follows the mouse, and feature clips rise out of the dark as they enter the viewport. All of it switches off under reduced motion.

**Key Characteristics:**
- Sticky 34px bar with workspace buttons, a centred clock and a GitHub star on the right.
- Square tiles on the ground colour with 10px outer and 6px inner gaps.
- Every tile opens with a title strip of short mono labels separated by middle dots.
- One lit tile at a time: a 2px gradient border from blue to purple.
- Terminal panes on a darker ground carry every copyable command.
- Real 9:16 phone footage as the main imagery.

## Colors

Tokyo Night, carried over literally: a blue-black ground, three steps of navy surfaces, periwinkle ink, and the theme's syntax accents used for the same jobs they do in a terminal.

### Primary
- **Tokyo Blue** (`blue`): the active workspace button, the Copy button, links, list markers, focus outlines and the start of the active border gradient.
- **Soft Purple** (`purple`): the end of the active border gradient, the "via" column in the log, and the Copy button's pressed state.

### Secondary
- **Lamp Amber** (`amber`): the GitHub star action only (bar link hover and the star button), plus quoted speech in `q` elements. Hover deepens to Light Amber (`amber-hover`).
- **Prompt Green** (`green`): inline code, the `$` prompt, command names in the facts list, and the deck's replies in the log.
- **Sky Cyan** (`cyan`): hover state for links and the Copy button.

### Neutral
- **Night Ground** (`ground`): the page background and the bar.
- **Window Navy** (`tile`): every tile's body.
- **Raised Navy** (`raised`): title strips, hover fills, hairline dividers between rows and log lines.
- **Inactive Border** (`edge`): the 2px tile border at rest, terminal borders, middle-dot separators. Dims to **Dim Border** (`edge-dim`) on unfocused tiles.
- **Terminal Black** (`term-ground`): terminal panes and their title strips.
- **Media Black** (`media-ground`): the fill behind videos and images before they load.
- **Bright** (`bright`): headings and step numbers only.
- **Periwinkle Ink** (`ink`): body text and the clock.
- **Quiet Ink** (`quiet`): ledes, list text, descriptions, first word of a title strip.
- **Label Grey** (`label`): title strips, timestamps, inactive workspace numbers, the footer.
- **Selection Navy** (`selection`): text selection background.

### Named Rules
**The Theme Is the Palette Rule.** Colours come from Tokyo Night and keep their terminal jobs: green for commands and success replies, purple for the source of an action, amber for quoted speech and the star. Don't introduce a colour the theme doesn't have.

**The One Lit Border Rule.** The blue-to-purple gradient appears on exactly one tile at a time, the focused one. It is a state, never decoration.

## Typography

**Display Font:** JetBrains Mono, self-hosted at 400, 500, 700 and 800 (with ui-monospace, monospace)
**Body Font:** the system sans stack (ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif)
**Label/Mono Font:** JetBrains Mono

**Character:** Mono for everything the desktop itself would render (bar, window titles, terminals, logs, headlines); system sans for the sentences a person reads. The headline in ExtraBold mono with tight negative tracking is the only loud thing on the page.

### Hierarchy
- **Display** (800, clamp up to 96px, 0.98): the single home headline. Bright, balanced wrap.
- **Headline** (800, clamp 30 to 56px, 1.02): one per workspace.
- **Title** (700, 18px, 1.25): clip titles, install steps; grows to clamp 20 to 26px in wide clip tiles and 22 to 30px in the lead clip; drops to 16px on phones.
- **Lede** (400, clamp 18 to 21px): the home lede, max 44ch. Section ledes use body size at max 62ch.
- **Body** (400, 17px, 1.6) and **Body small** (15px): prose, clip step lists, row descriptions.
- **Code** (mono 15px in terminals; inline code at 0.92em in green).
- **Log** (mono 14px, 1.55): the evening log and facts.
- **Bar** (mono 500, 13px) and **Label** (mono 500, 12px): the bar and every title strip.

### Named Rules
**The Scale Alone Rule.** Hierarchy is made by size and weight, not colour blocks, badges or cards. One headline per workspace, then a steep drop.

**The Desktop Speaks Mono Rule.** Anything the operating system would draw (bar, titles, terminals, timestamps, command names) is JetBrains Mono. Sentences are sans.

## Layout

The page is one continuous desktop: `main` is a single column of workspaces with 40px (four outer gaps) between them and a 10px outer gap around everything. Each workspace is a CSS grid of tiles with a 6px inner gap. The bar is sticky at 34px, and anchor scrolling is padded to clear it.

- **Workspace 1 (home):** fills the first viewport (at least 600px). A flexible master tile on the left; on the right, a tile whose width is computed so the highlight video sits at 9:16 at full height.
- **Workspace 2 (clips):** four columns. A full-width intro tile, then clip tiles; wide clips span two columns with the video and text side by side.
- **Workspace 3 (log):** a wide log tile plus a narrow screenshot tile (min(24vw, 340px)).
- **Workspace 4 (install):** 1.4fr steps tile, 1fr notes tile.
- **Workspace 5 (details):** two equal tiles, then a full-width star tile.

Tile body padding is clamp(20px, 3.4vw, 48px); list-style tiles use clamp(18px, 3vw, 32–36px) side padding.

**Responsive:**
- **At 1100px and below:** clips go to three columns with dense packing; wide and tail clips span the full row with the video at 34% width.
- **At 860px and below:** every workspace stacks to one column; the hero video becomes 9:16 capped at 78svh; clips go to two columns; the clock hides; the screenshot tile caps at 460px.
- **At 560px and below:** outer gap drops to 6px; the current workspace label and the GitHub text hide; clips become single rows with the video at 42% beside its text; the log collapses to two columns; the terminal stacks its Copy button full-width underneath, the command breaks onto a continuation line, and the line fades at the right edge only when it actually overflows.

## Elevation & Depth

Flat. There are no shadows anywhere. Depth is conveyed the way a tiling compositor does it: tonal steps from ground to tile to raised, gaps that show the ground between windows, and the focused tile's lit border. Unfocused tiles recede by dimming their title strip and media to 60% opacity and their border to the dim border colour. Clip videos sit at brightness 0.5 and saturation 0.7 until they scroll into view, then clear to full.

### Named Rules
**The Compositor Depth Rule.** Depth is gaps, tonal steps and focus, never drop shadows or glows.

## Shapes

Square. Tiles, terminals, buttons, step numbers and title strips have no radius; borders are 2px on tiles and 1px on terminals, buttons and dividers. The only rounding is inherited from real artefacts: the workspace buttons (4px, as Waybar draws them) and the logo (5px in the bar, 12px at 56px on the home tile). Rows inside tiles are separated by 1px raised hairlines, with the last row's line removed.

## Components

### Bar
Waybar, transposed. Ground background, 1px raised bottom line, three-column grid. Left: the 20px logo then workspace buttons 1 to 5. The current button fills blue with ground-coloured text and reveals its name (home, watch, evening, install, details); others are label grey and fill raised on hover. Centre: a clock in tabular figures, updated every 15s. Right: GitHub icon and "Star on GitHub" in quiet ink, amber on hover.

### Tiles
- **Corner Style:** square (0).
- **Background:** window navy.
- **Border:** 2px inactive border at rest; dim border when unfocused; the blue-to-purple gradient on the focused tile (done with a padding-box/border-box background pair over a transparent border).
- **Title strip:** raised background, 8px 12px padding, 12px mono label grey, single line. Three short labels (feature · tab · gesture, or name · context · workspace N) joined by inactive-border middle dots; the first label in quiet ink.
- **Transitions:** opacity and border colour over 0.35s ease.

### Terminal Pane
The home of every copyable command. Terminal black background, 1px inactive border, its own title strip on the same black with a raised hairline beneath. The command is mono 15px in ink with a green `$ ` prompt that can't be selected. The Copy button is attached flush on the right, separated by a 1px border.

### Buttons
- **Copy (primary):** square, blue fill, ground text, mono 800 14px, 0 22px padding, full terminal height. Hover cyan, pressed purple. On click the label reads "Copied" (or "Selected" if the clipboard is refused, with the command text selected) for 1.6s, announced through a polite live region.
- **Star (secondary):** square, amber fill, ground text, mono 800 15px with an 18px star icon, 16px 22px padding. Hover light amber.
- **Focus:** a 2px blue outline offset 2px on everything focusable.

### Clip Tiles
A tile holding a muted, looping 9:16 phone clip with a poster and a descriptive label, then a title and a three-step ordered list whose numbers are blue mono. Wide clips put the video at half width beside the text. Clips play only while 40% visible, lit on entry with a 0.9s cubic-bezier(.16, 1, .3, 1) filter clear, and pause when they leave. Under reduced motion every clip shows controls and full brightness instead of autoplaying.

### Log
A mono list in three columns (7ch time in label grey, 8ch via in purple, then the action in ink with the deck's reply beneath in green), separated by raised hairlines.

### Install Steps
Numbered with a 34px square counter (raised fill, inactive border, bright mono 800 15px) beside a title and quiet description; the first step embeds a terminal pane.

### Facts and Rows
Definition lists with green mono command names over quiet descriptions; detail rows with bright mono names over quiet descriptions, divided by hairlines.

## Do's and Don'ts

### Do:
- **Do** put new content in a tile with a three-label title strip, inside a workspace grid with 6px inner gaps.
- **Do** keep exactly one lit tile at a time, chosen by focus-follows-mouse or the tile nearest the middle of the screen.
- **Do** put every command a visitor should run in a terminal pane with an attached Copy button.
- **Do** use real phone and desktop footage at 9:16, dark until it enters the viewport.
- **Do** give every new workspace a bar button and a `data-ws` number so the bar tracks it.
- **Do** honour reduced motion: no tile-open animation, no smooth scroll, clips with controls instead of autoplay.

### Don't:
- **Don't** round tiles, terminals or buttons; only the workspace buttons and the logo carry a radius.
- **Don't** add drop shadows or glows; depth comes from gaps, tonal steps and the lit border.
- **Don't** use the blue-to-purple gradient on anything but the focused tile's border.
- **Don't** add colours outside Tokyo Night, or move a theme colour off its terminal job.
- **Don't** set prose in mono or the bar, titles and code in the sans.
- **Don't** lower title-strip and timestamp text back to the theme's darker comment grey; the label grey (`label`) is the legible floor on raised navy.
