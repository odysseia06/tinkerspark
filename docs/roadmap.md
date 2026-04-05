# Roadmap

Items roughly ordered by value and feasibility. No timelines — pick what matters next.

## Near-term

### UX polish
- Tab reordering via drag
- Ctrl+Tab / Ctrl+Shift+Tab to cycle tabs
- Ctrl+1..9 to jump to tab by index
- Per-tab search state (currently shared across tabs)
- Diff tab: show file names more prominently in the side headers
- Scroll position preservation when switching tabs

### Diff improvements
- Support diffing regions of different lengths (currently requires equal-length)
- Inline diff view (single pane, interleaved) as alternative to side-by-side
- Diff statistics in the tab name (e.g. "file1 vs file2 (3 changes)")

### Save workflow
- "Save As" for file tabs (not just "Save Patched Copy")
- Prompt to save on app quit if any tab is dirty
- Save individual diff sides without dialog each time (remember last path)

### Search
- Search within diff views
- Search-and-replace (same-length patches)
- Highlight all search matches in the hex view

## Medium-term

### General-purpose hex editing
- Insert and delete bytes (variable-length patches, file resize)
- Type-over editing directly in the hex grid
- Clipboard copy/paste (hex and raw bytes)
- Fill region with pattern
- This transitions Tinkerspark from a read-mostly inspector to a full hex editor

### Additional format analyzers
- X.509 / DER / PEM certificates
- SSH key formats (OpenSSH, PuTTY)
- PDF structure
- ELF / PE binary headers
- Each as a new `format-*` crate implementing the `Analyzer` trait

### Data inspector panel
- Configurable decode of selection: timestamps, UUIDs, IP addresses, ASN.1 tags
- Editable — change a decoded value and apply as patch

### Hex view enhancements
- Column count configuration (currently fixed at 16)
- Byte grouping options (1/2/4/8 bytes)
- Color coding by byte value ranges
- Minimap / scroll overview showing diff/patch locations

### Diff enhancements
- Three-way diff (base + left + right)
- Format-aware diff (align by packet boundaries, not just byte offset)
- Diff of patched vs original within a single file tab

## Longer-term

### CLI mode
- Headless diff, patch-apply, and format-dump commands
- Scriptable via stdin/stdout for CI pipelines
- Same core crates, no UI dependency

### Plugin system
- Dynamic analyzer loading (shared libraries or WASM)
- User-defined structure templates (binary format DSL)

### Collaboration
- Export/import patch sets as standalone files
- Share diff reports with byte-level annotations

### Performance
- Lazy file loading for multi-GB files (currently reads full file)
- Background analysis (move parsing off the UI thread)
- Incremental diff (re-diff only changed regions after a patch)
