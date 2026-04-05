# CLAUDE.md

## What This Repo Is
Tinkerspark is a desktop Rust workstation for inspecting, diffing, and carefully patching binary files — especially cryptographic formats like OpenPGP.

Core principles:
- Raw bytes first, structure second
- All file access is read-only; edits are patch overlays
- Save flows create a new file, never overwrite the original
- Destructive actions never by default

## Version
Alpha 0.1.0.

## Docs
- `docs/architecture.md` — crate map, dependency graph, design decisions
- `docs/product.md` — what the app does, feature inventory
- `docs/roadmap.md` — prioritized next steps

## Crate Map

```
crates/
  core-types/       — ByteRange, FileHandle, NodeId, Diagnostic, DetectedKind
  core-bytes/       — ByteSource trait, file open (mmap/buffered), content-based kind sniffing
  core-hexview/     — HexViewState, row building, virtual scroll math, search, selection
  core-patch/       — PatchSet, PatchHistory (undo/redo), PatchedView (read-through overlay)
  core-diff/        — Byte-level diff engine, ChangedRange, DiffNavigator
  core-analyze/     — Analyzer trait, AnalyzerRegistry, AnalysisReport/AnalysisNode
  format-openpgp/   — OpenPGP analyzer (Sequoia + custom boundary walker)
  infra-io/         — save_patched_copy (write patched bytes to new file)
  infra-session/    — SessionState persistence (recent files, bookmarks, window size, dock layout, open tabs)
  app-desktop/      — eframe/egui desktop app, all UI code
```

## App Architecture (app-desktop)

### State model (`state.rs`)
- `AppState` owns everything: workspace tabs, analyzer registry, session, UI state.
- `WorkspaceTab` enum: `File { file: OpenFile, analysis: Option<AnalysisState> }` or `Diff(DiffSession)`.
- `tabs: Vec<WorkspaceTab>` + `active_tab: usize` — the tabbed workspace.
- Accessor methods: `active_file()`, `active_file_mut()`, `active_diff()`, `active_diff_mut()`, `active_analysis()`.
- Direct field access (`self.tabs.get_mut(self.active_tab)`) is used where split borrows are needed (e.g. `reanalyze` borrows both `tabs` and `registry`).

### UI layout (`app.rs`)
- Single `egui_dock` layout (never rebuilt). `PaneKind`: Hex (Editor), Structure, Metadata, Patches, Diagnostics, Bookmarks.
- The Hex/Editor pane is the workspace: renders a tab bar at top, dispatches to file hex view or diff view based on active tab type.
- Diff tabs render left/right hex panes side-by-side (`SidePanel` + `CentralPanel`) with summary panel at bottom — all within the single Editor dock pane.

### Key rendering files
- `hex_pane.rs` — tab bar + file hex view (toolbar, virtual-scroll hex grid, keyboard nav, mouse selection).
- `diff_pane.rs` — `render_diff_tab()` entry point, `render_diff_hex_side()` for each side, `render_diff_summary()` for controls/change list.
- `panes.rs` — side pane renderers (Metadata, Structure, Patches, Diagnostics, Bookmarks). All read from active tab via `state.active_file()` / `state.active_analysis()`.

### Diff features
- Merged regions tracked in `DiffSession.merged_regions` for persistent teal highlighting after merge.
- Diff bytes rendered through `PatchedView` so merged content is visible.
- Clickable diff-highlighted bytes navigate to that change in the navigator.
- Undo removes merged-region highlights via overlap check in `recompute()`.

### Tab lifecycle
- `request_close_tab()` checks dirty state; dirty tabs get a confirmation dialog (`pending_close_tab`).
- `close_tab()` adjusts `active_tab` correctly when removing tabs to the left.
- Edit dialog is tab-scoped: `edit_dialog_tab` records which tab it was opened for; apply targets that tab, not whatever is active.

### Session persistence (`infra-session`)
- `last_open_files: Vec<PathBuf>` + `last_active_tab: usize` round-trip all file tabs across restart.
- Falls back to legacy `last_open_file: Option<PathBuf>` for old session files.
- Diff tabs are not persisted (no meaning without in-memory merge state).
- Dock layout serialized as JSON blob.

## Architectural Guardrails
- `ByteSource` is the boundary between file IO and everything else.
- Format analyzers sit behind the `Analyzer` trait in `core-analyze`. Add new formats by implementing the trait in a new `format-*` crate and registering in `AppState::new()`.
- Structured views must map back to exact byte ranges.
- Detect file kind by content first, extension second.

## Working Style
- Make small, coherent changes.
- Finish with `cargo fmt`, `cargo check`, and `cargo test`.
- Use available Rust skills and MCP tools (rust-analyzer, coding-guidelines, etc.) proactively when writing or reviewing code.
