# Product

## What Tinkerspark Is
A desktop workstation for inspecting, diffing, and carefully patching binary files. Primary use case: cryptographic key files (OpenPGP), but the core is format-agnostic.

## What Tinkerspark Is Not (yet)
- Not a key manager, signer, or encryption tool
- Not yet a full general-purpose hex editor — currently patches are same-length overlays only; insert/delete and resize are planned
- Not a crypto suite

## Target Users
- Security researchers examining key material
- Developers debugging binary file formats
- Anyone who needs to compare two binary files byte-by-byte and selectively merge differences

## Core Capabilities (alpha 0.1.0)

### Hex Viewer
- Virtual-scrolling hex grid with ASCII preview
- Keyboard navigation (arrows, Page Up/Down, Home/End, Ctrl+Home/End)
- Mouse click and drag selection
- Selection metadata: hex preview, ASCII preview, u8/u16/u32/u64 LE/BE decoding
- Jump to offset (hex or decimal)
- Chunked search (hex pattern or text, forward/backward with wrap)

### Patch Layer
- Edit selection with hex or text input (same-length replacement only)
- Undo/redo with full history (handles overlapping patches via split semantics)
- Save as patched copy (new file, never overwrites original)
- Revert all patches

### Binary Diff
- Side-by-side hex comparison of two files
- Synchronized scrolling
- Change navigator (first/prev/next/last, change counter)
- Per-change merge buttons (L>R, R>L) and bulk merge (Use All Left/Right)
- Merged regions highlighted in teal; active diffs in red; focused diff in orange
- Clickable diff bytes to select that change
- Undo/redo per side
- Export diff report as text

### OpenPGP Analyzer
- Auto-detects OpenPGP files (binary and ASCII-armored) by content
- Packet tree with Sequoia-parsed fields (algorithm, key ID, creation time, etc.)
- Byte-range mapping — click a packet node to highlight its bytes in the hex view
- Falls back to boundary-only analysis when Sequoia parsing fails
- Re-analyze after patching

### Workspace
- Tabbed interface: multiple files and diffs open simultaneously
- Tab bar with dirty indicators, middle-click close, context menu close
- Confirmation dialog before closing dirty tabs
- Side panes: Structure, Metadata, Patches, Diagnostics, Bookmarks — all reflect the active tab

### Session Persistence
- Restores all open file tabs, active tab, window size, and dock layout across restart
- Recent files list (up to 20)
- Per-file bookmarks at byte offsets

### Other
- Command palette (Ctrl+P) with fuzzy search
- Dark/light theme toggle
- Keyboard shortcuts for all common operations
