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

# Rust coding guidelines

* Prioritize code correctness and clarity. Speed and efficiency are secondary priorities unless otherwise specified.
* Do not write organizational or comments that summarize the code. Comments should only be written in order to explain "why" the code is written in some way in the case there is a reason that is tricky / non-obvious.
* Prefer implementing functionality in existing files unless it is a new logical component. Avoid creating many small files.
* Avoid using functions that panic like `unwrap()`, instead use mechanisms like `?` to propagate errors.
* Be careful with operations like indexing which may panic if the indexes are out of bounds.
* Never silently discard errors with `let _ =` on fallible operations. Always handle errors appropriately:
  - Propagate errors with `?` when the calling function should handle them
  - Use `.log_err()` or similar when you need to ignore errors but want visibility
  - Use explicit error handling with `match` or `if let Err(...)` when you need custom logic
  - Example: avoid `let _ = client.request(...).await?;` - use `client.request(...).await?;` instead
* When implementing async operations that may fail, ensure errors propagate to the UI layer so users get meaningful feedback.
* Never create files with `mod.rs` paths - prefer `src/some_module.rs` instead of `src/some_module/mod.rs`.
* When creating new crates, prefer specifying the library root path in `Cargo.toml` using `[lib] path = "...rs"` instead of the default `lib.rs`, to maintain consistent and descriptive naming (e.g., `gpui.rs` or `main.rs`).
* Avoid creative additions unless explicitly requested
* Use full words for variable names (no abbreviations like "q" for "queue")
* Use variable shadowing to scope clones in async contexts for clarity, minimizing the lifetime of borrowed references.
  Example:
  ```rust
  executor.spawn({
      let task_ran = task_ran.clone();
      async move {
          *task_ran.borrow_mut() = true;
      }
  });
  ```
