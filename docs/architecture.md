# Architecture

## Overview

Tinkerspark is a multi-crate Rust workspace. The desktop app (`app-desktop`) depends on core libraries that are UI-agnostic and independently testable.

```
                  ┌──────────────┐
                  │ app-desktop  │  eframe/egui UI
                  └──────┬───────┘
         ┌───────────────┼───────────────┐
         v               v               v
   ┌───────────┐  ┌────────────┐  ┌────────────┐
   │ core-hex  │  │ core-diff  │  │ core-patch │
   │   view    │  │            │  │            │
   └─────┬─────┘  └─────┬──────┘  └─────┬──────┘
         │              │               │
         v              v               v
     ┌──────────┐  ┌──────────┐  ┌──────────┐
     │core-bytes│  │core-types│  │core-types│
     └──────────┘  └──────────┘  └──────────┘
         │
         v
   ┌───────────┐      ┌────────────┐
   │core-analyze│◄────│format-openpgp│
   └───────────┘      └────────────┘

   ┌──────────┐  ┌──────────────┐
   │ infra-io │  │infra-session │
   └──────────┘  └──────────────┘
```

## Crate Responsibilities

### core-types
Shared types with no dependencies: `ByteRange`, `FileHandle`, `DetectedKind`, `NodeId`, `Diagnostic`, `Severity`.

### core-bytes
`ByteSource` trait — the central abstraction for reading bytes. Implementations: `MemoryByteSource` (tests), `MmapByteSource` (production). Also handles file opening and content-based kind sniffing (OpenPGP binary, armored, text, generic binary).

### core-hexview
Pure logic for the hex viewer — no UI code. `HexViewState` (cursor, scroll offset, selection, drag state), row building, offset formatting, virtual scroll math, chunked search (forward/backward with wrap), selection metadata (u8/u16/u32/u64 LE/BE decoding).

### core-patch
Immutable-base patch system. `PatchSet` stores non-overlapping same-length patches with split-on-overlap semantics. `PatchHistory` adds undo/redo. `PatchedView` implements `ByteSource` to transparently overlay patches on a base source — consumers read patched bytes without materialized copies.

### core-diff
Byte-level positional diff engine. Compares two `ByteSource`s in aligned chunks, produces `Vec<ChangedRange>` with coalescing. `DiffNavigator` tracks focused change index for UI navigation.

### core-analyze
`Analyzer` trait with `can_analyze()` (confidence scoring) and `analyze()` (produces `AnalysisReport`). `AnalyzerRegistry` auto-selects the best analyzer by confidence. `AnalysisReport` contains a tree of `AnalysisNode`s with labels, fields, byte ranges, and diagnostics.

### format-openpgp
OpenPGP analyzer using Sequoia for packet parsing and a custom boundary walker for exact byte-range tracking. Handles armored files (dearmor then parse) and binary. Falls back to boundary-only analysis when Sequoia fails.

### infra-io
`save_patched_copy()` — writes base + patches to a new file. Validates target differs from source.

### infra-session
`SessionState` persistence as JSON in `~/.tinkerspark/session.json`. Stores: recent files, window geometry, bookmarks, open file tab paths, active tab index, dock layout blob.

### app-desktop
eframe/egui desktop application. Uses `egui_dock` for panel arrangement. Key modules:

- **state.rs** — `AppState` with tabbed workspace model (`Vec<WorkspaceTab>`), accessor methods, file open/diff open, analysis lifecycle.
- **app.rs** — eframe::App impl, menu bar, keyboard shortcuts, command palette, edit dialog, close-tab confirmation dialog, scroll sync.
- **hex_pane.rs** — workspace tab bar + file hex view (toolbar, virtual-scroll grid, mouse interaction, selection status).
- **diff_pane.rs** — diff tab layout (left/right panels + summary), diff row rendering with color highlighting (red=diff, orange=focused, teal=merged), clickable diff bytes.
- **panes.rs** — side pane renderers that read from the active tab.

## Key Design Decisions

### Patches over immutable bytes
Files are never modified. Edits create patches that overlay the original bytes. `PatchedView` makes this transparent to all consumers (hex view, search, diff, analyzers). Save writes a new file.

### Tabbed workspace
Multiple files and diffs coexist as tabs. No mode switching or layout rebuilding. Side panes (Structure, Metadata, etc.) reflect the active tab. The dock layout is for panel arrangement; the tab bar is rendered inside the Editor pane.

### Diff as a tab
A diff comparison is just another `WorkspaceTab::Diff` variant. It renders its own left/right/summary layout within the Editor pane using egui panels. Merged regions are tracked separately for persistent highlighting. Undo cleans up merged highlights via overlap detection in `recompute()`.

### Analyzer trait boundary
Format-specific parsing is behind the `Analyzer` trait. The binary engine (hex view, patches, diff) knows nothing about file formats. New formats are added by implementing the trait in a new crate and registering it.

### Content-first detection
File kind is detected by inspecting leading bytes (magic numbers, armor headers), falling back to extension only when content is ambiguous.
