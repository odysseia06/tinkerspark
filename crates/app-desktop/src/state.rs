use std::path::Path;

use tinkerspark_core_analyze::{AnalysisReport, AnalyzerRegistry};
use tinkerspark_core_bytes::{BackendKind, ByteSource};
use tinkerspark_core_diff::{DiffNavigator, DiffResult};
use tinkerspark_core_hexview::HexViewState;
use tinkerspark_core_patch::PatchHistory;
use tinkerspark_core_patch::PatchedView;
use tinkerspark_core_types::{ByteRange, FileHandle, NodeId};
use tinkerspark_format_generic::Sensitivity;
use tinkerspark_infra_session::SessionState;

/// The state of a single open file.
pub struct OpenFile {
    pub handle: FileHandle,
    pub source: Box<dyn ByteSource>,
    pub backend: BackendKind,
    pub hex: HexViewState,
    pub patches: PatchHistory,
}

/// Analysis state for an open file.
pub struct AnalysisState {
    pub report: AnalysisReport,
    /// Whether the analysis is stale (file has been edited since last run).
    pub stale: bool,
    /// Whether the analyzed file was armored/PEM-encoded. When true, node byte
    /// ranges refer to decoded content and cannot be mapped to file offsets, so
    /// hex jump/highlight is disabled.
    pub armored: bool,
    /// The currently selected node in the structure tree, if any.
    pub selected_node: Option<NodeId>,
    /// Byte range of the selected node, for hex highlighting.
    pub selected_range: Option<ByteRange>,
}

/// Check whether an analysis report indicates that byte ranges refer to
/// decoded content (armored/PEM-encoded) rather than the original file.
fn has_decoded_ranges(report: &AnalysisReport) -> bool {
    report
        .diagnostics
        .iter()
        .any(|d| d.message.contains("ASCII-armored") || d.message.contains("PEM-encoded"))
}

/// Which diff pane was scrolled most recently (for sync propagation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollAuthority {
    Left,
    Right,
}

/// Which side of the diff was last modified (for Ctrl+Z/Y targeting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSide {
    Left,
    Right,
}

/// A region that has been merged between sides, kept for highlighting.
#[derive(Debug, Clone)]
pub struct MergedRegion {
    pub left: ByteRange,
    pub right: ByteRange,
}

/// State for a two-file diff comparison session.
pub struct DiffSession {
    pub left: OpenFile,
    pub right: OpenFile,
    pub result: DiffResult,
    pub navigator: DiffNavigator,
    /// Whether scroll is synchronized between left and right panes.
    pub sync_scroll: bool,
    /// Which pane was scrolled most recently. The other pane follows.
    pub scroll_authority: ScrollAuthority,
    /// Which side was last modified by a merge. Used by Ctrl+Z/Y.
    pub last_merged_side: Option<DiffSide>,
    /// Ranges that have been merged, for persistent highlighting.
    pub merged_regions: Vec<MergedRegion>,
}

impl DiffSession {
    /// Recompute the diff result, reading through each side's patch overlay
    /// so that merged changes are reflected.
    pub fn recompute(&mut self) -> Result<(), String> {
        let left_view = PatchedView::new(&*self.left.source, self.left.patches.patches());
        let right_view = PatchedView::new(&*self.right.source, self.right.patches.patches());
        let config = tinkerspark_core_diff::DiffConfig::default();
        self.result = tinkerspark_core_diff::compute_diff(&left_view, &right_view, &config)
            .map_err(|e| e.to_string())?;
        self.navigator = DiffNavigator::new(&self.result);

        // Remove merged regions that overlap with current changes (merge was undone).
        self.merged_regions.retain(|mr| {
            !self.result.changes.iter().any(|change| {
                ranges_overlap(&mr.left, &change.left) || ranges_overlap(&mr.right, &change.right)
            })
        });

        Ok(())
    }

    /// Merge a single change by copying the left side's bytes into the right
    /// side as a patch.
    pub fn merge_to_right(&mut self, change_index: usize) -> Result<(), String> {
        let change = self
            .result
            .changes
            .get(change_index)
            .ok_or("change index out of bounds")?
            .clone();

        if change.left.length() != change.right.length() {
            return Err("Cannot merge: regions have different lengths".into());
        }
        if change.left.is_empty() {
            return Err("Cannot merge: empty range".into());
        }

        let left_view = PatchedView::new(&*self.left.source, self.left.patches.patches());
        let bytes = left_view
            .read_range(change.left)
            .map_err(|e| format!("read left: {e}"))?
            .into_owned();

        let label = format!("Merge L→R @0x{:X}", change.right.offset());
        self.right
            .patches
            .apply(change.right, bytes, label)
            .map_err(|e| format!("patch right: {e}"))?;

        self.last_merged_side = Some(DiffSide::Right);
        self.merged_regions.push(MergedRegion {
            left: change.left,
            right: change.right,
        });
        self.recompute()
    }

    /// Merge a single change by copying the right side's bytes into the left
    /// side as a patch.
    pub fn merge_to_left(&mut self, change_index: usize) -> Result<(), String> {
        let change = self
            .result
            .changes
            .get(change_index)
            .ok_or("change index out of bounds")?
            .clone();

        if change.left.length() != change.right.length() {
            return Err("Cannot merge: regions have different lengths".into());
        }
        if change.right.is_empty() {
            return Err("Cannot merge: empty range".into());
        }

        let right_view = PatchedView::new(&*self.right.source, self.right.patches.patches());
        let bytes = right_view
            .read_range(change.right)
            .map_err(|e| format!("read right: {e}"))?
            .into_owned();

        let label = format!("Merge R→L @0x{:X}", change.left.offset());
        self.left
            .patches
            .apply(change.left, bytes, label)
            .map_err(|e| format!("patch left: {e}"))?;

        self.last_merged_side = Some(DiffSide::Left);
        self.merged_regions.push(MergedRegion {
            left: change.left,
            right: change.right,
        });
        self.recompute()
    }

    /// Whether a change at the given index can be merged (equal-length, non-empty).
    pub fn can_merge(&self, change_index: usize) -> bool {
        self.result
            .changes
            .get(change_index)
            .is_some_and(|c| c.left.length() == c.right.length() && !c.left.is_empty())
    }

    /// Undo on a specific side, then recompute the diff.
    pub fn undo_side(&mut self, side: DiffSide) -> bool {
        let undone = match side {
            DiffSide::Left => self.left.patches.undo(),
            DiffSide::Right => self.right.patches.undo(),
        };
        if undone {
            let _ = self.recompute();
        }
        undone
    }

    /// Redo on a specific side, then recompute the diff.
    pub fn redo_side(&mut self, side: DiffSide) -> bool {
        let redone = match side {
            DiffSide::Left => self.left.patches.redo(),
            DiffSide::Right => self.right.patches.redo(),
        };
        if redone {
            let _ = self.recompute();
        }
        redone
    }

    /// Revert all patches on a specific side, then recompute the diff.
    pub fn revert_side(&mut self, side: DiffSide) {
        match side {
            DiffSide::Left => self.left.patches.revert_all(),
            DiffSide::Right => self.right.patches.revert_all(),
        }
        self.merged_regions.clear();
        let _ = self.recompute();
    }

    /// Whether either side has been modified.
    pub fn is_dirty(&self) -> bool {
        self.left.patches.is_dirty() || self.right.patches.is_dirty()
    }
}

// ── Workspace tab model ──────────────────────────────────────────────

/// A workspace tab — either a single file or a diff comparison.
pub enum WorkspaceTab {
    File {
        file: OpenFile,
        analysis: Option<AnalysisState>,
    },
    Diff(DiffSession),
}

impl WorkspaceTab {
    /// Display name for the tab bar.
    pub fn name(&self) -> String {
        match self {
            WorkspaceTab::File { file, .. } => file
                .handle
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| file.handle.path.display().to_string()),
            WorkspaceTab::Diff(diff) => {
                let left = diff
                    .left
                    .handle
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "left".into());
                let right = diff
                    .right
                    .handle
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "right".into());
                format!("{left} vs {right}")
            }
        }
    }

    /// Whether the tab has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        match self {
            WorkspaceTab::File { file, .. } => file.patches.is_dirty(),
            WorkspaceTab::Diff(diff) => diff.is_dirty(),
        }
    }
}

// ── Top-level application state ──────────────────────────────────────

/// Top-level application state.
pub struct AppState {
    /// Open workspace tabs (files and diffs).
    pub tabs: Vec<WorkspaceTab>,
    /// Index of the currently active tab.
    pub active_tab: usize,
    pub registry: AnalyzerRegistry,
    /// Currently selected generic-analyzer sensitivity. Persisted in session.
    pub generic_sensitivity: Sensitivity,
    pub session: SessionState,
    pub status_message: Option<String>,
    pub jump_to_input: String,
    pub search_input: String,
    pub search_hex_mode: bool,
    /// Edit dialog state.
    pub edit_input: String,
    pub edit_hex_mode: bool,
    pub show_edit_dialog: bool,
    /// The tab index the edit dialog was opened for.
    pub edit_dialog_tab: usize,
    /// Command palette state.
    pub show_command_palette: bool,
    pub command_query: String,
    /// When set, a confirmation dialog is shown before closing this tab.
    pub pending_close_tab: Option<usize>,
}

// ── Workspace accessors ──────────────────────────────────────────────

impl AppState {
    pub fn active_tab(&self) -> Option<&WorkspaceTab> {
        self.tabs.get(self.active_tab)
    }

    pub fn active_tab_mut(&mut self) -> Option<&mut WorkspaceTab> {
        self.tabs.get_mut(self.active_tab)
    }

    pub fn active_file(&self) -> Option<&OpenFile> {
        match self.active_tab()? {
            WorkspaceTab::File { file, .. } => Some(file),
            _ => None,
        }
    }

    pub fn active_file_mut(&mut self) -> Option<&mut OpenFile> {
        match self.active_tab_mut()? {
            WorkspaceTab::File { file, .. } => Some(file),
            _ => None,
        }
    }

    pub fn active_analysis(&self) -> Option<&AnalysisState> {
        match self.active_tab()? {
            WorkspaceTab::File { analysis, .. } => analysis.as_ref(),
            _ => None,
        }
    }

    pub fn active_diff(&self) -> Option<&DiffSession> {
        match self.active_tab()? {
            WorkspaceTab::Diff(diff) => Some(diff),
            _ => None,
        }
    }

    pub fn active_diff_mut(&mut self) -> Option<&mut DiffSession> {
        match self.active_tab_mut()? {
            WorkspaceTab::Diff(diff) => Some(diff),
            _ => None,
        }
    }

    pub fn is_diff_active(&self) -> bool {
        matches!(self.active_tab(), Some(WorkspaceTab::Diff(_)))
    }

    /// Request closing a tab. If the tab is dirty, sets `pending_close_tab`
    /// so the UI can show a confirmation dialog. Clean tabs close immediately.
    pub fn request_close_tab(&mut self, index: usize) {
        if index >= self.tabs.len() {
            return;
        }
        if self.tabs[index].is_dirty() {
            self.pending_close_tab = Some(index);
        } else {
            self.close_tab(index);
        }
    }

    /// Close a workspace tab by index unconditionally (no dirty check).
    pub fn close_tab(&mut self, index: usize) {
        if index >= self.tabs.len() {
            return;
        }
        self.pending_close_tab = None;
        self.tabs.remove(index);
        if self.tabs.is_empty() {
            self.active_tab = 0;
        } else if index < self.active_tab {
            // Removed a tab to the left — shift to keep the same tab active.
            self.active_tab -= 1;
        } else if self.active_tab >= self.tabs.len() {
            // Removed the rightmost tab while it was active.
            self.active_tab = self.tabs.len() - 1;
        }
    }
}

// ── Construction and file operations ─────────────────────────────────

impl AppState {
    pub fn new() -> Self {
        Self::with_session(tinkerspark_infra_session::load_session())
    }

    /// Construct an AppState from an explicit SessionState. Used by `new()`
    /// and by tests that need to skip disk IO.
    pub fn with_session(session: SessionState) -> Self {
        let generic_sensitivity = session
            .generic_sensitivity
            .as_deref()
            .map(Sensitivity::from_label)
            .unwrap_or_default();
        let registry = build_registry(generic_sensitivity);

        Self {
            tabs: Vec::new(),
            active_tab: 0,
            registry,
            generic_sensitivity,
            session,
            status_message: None,
            jump_to_input: String::new(),
            search_input: String::new(),
            search_hex_mode: false,
            edit_input: String::new(),
            edit_hex_mode: true,
            show_edit_dialog: false,
            edit_dialog_tab: 0,
            show_command_palette: false,
            command_query: String::new(),
            pending_close_tab: None,
        }
    }

    /// Switch the generic-analyzer sensitivity, rebuild the registry to pick
    /// up the new mode, persist the choice into the in-memory session, and
    /// re-run analysis on the active file so the change is visible without a
    /// manual reload.
    pub fn set_generic_sensitivity(&mut self, mode: Sensitivity) {
        if self.generic_sensitivity == mode {
            return;
        }
        self.generic_sensitivity = mode;
        self.registry = build_registry(mode);
        self.session.generic_sensitivity = Some(mode.label().to_string());
        if matches!(self.active_tab(), Some(WorkspaceTab::File { .. })) {
            self.reanalyze();
        }
        self.status_message = Some(format!("Generic analyzer sensitivity: {}", mode.label()));
    }

    pub fn open(&mut self, path: &Path) {
        match tinkerspark_core_bytes::open_file(path) {
            Ok((source, handle, backend)) => {
                tracing::info!(path = %handle.path.display(), "file opened successfully");
                self.status_message = Some(format!("Opened: {}", handle.path.display()));
                self.session.add_recent(handle.path.clone());
                let file_len = source.len();

                // Auto-analyze if a matching analyzer exists.
                let analysis_result = self.registry.auto_analyze(&handle, &*source);
                let analysis = match analysis_result {
                    Some(Ok(report)) => {
                        let node_count = report.root_nodes.len();
                        tracing::info!(
                            analyzer = %report.analyzer_id,
                            nodes = node_count,
                            "analysis complete"
                        );
                        self.status_message = Some(format!(
                            "Opened: {} ({}: {} nodes)",
                            handle.path.display(),
                            report.analyzer_id,
                            node_count,
                        ));
                        let armored = has_decoded_ranges(&report);
                        Some(AnalysisState {
                            report,
                            stale: false,
                            armored,
                            selected_node: None,
                            selected_range: None,
                        })
                    }
                    Some(Err(e)) => {
                        tracing::warn!(error = %e, "analysis failed");
                        None
                    }
                    None => None,
                };

                let file = OpenFile {
                    handle,
                    source,
                    backend,
                    hex: HexViewState::new(file_len),
                    patches: PatchHistory::new(file_len),
                };

                self.tabs.push(WorkspaceTab::File { file, analysis });
                self.active_tab = self.tabs.len() - 1;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to open file");
                self.status_message = Some(format!("Error opening file: {e}"));
            }
        }
    }

    /// Mark the analysis as stale (called after patching).
    pub fn mark_analysis_stale(&mut self) {
        if let Some(WorkspaceTab::File {
            analysis: Some(a), ..
        }) = self.active_tab_mut()
        {
            a.stale = true;
        }
    }

    /// Persist session state to disk. Captures open file paths,
    /// active tab index, and dock layout.
    pub fn save_session_with_layout(&mut self, dock_layout: Option<serde_json::Value>) {
        // Save all file tab paths (diff tabs are not restored).
        self.session.last_open_files = self
            .tabs
            .iter()
            .filter_map(|tab| match tab {
                WorkspaceTab::File { file, .. } => Some(file.handle.path.clone()),
                _ => None,
            })
            .collect();
        // Legacy field — first file tab for old session files.
        self.session.last_open_file = self.session.last_open_files.first().cloned();
        self.session.last_active_tab = self.active_tab;
        self.session.dock_layout = dock_layout;
        self.session.generic_sensitivity = Some(self.generic_sensitivity.label().to_string());
        tinkerspark_infra_session::save_session(&self.session);
    }

    /// Re-run analysis on the current file, reading through the patch overlay.
    pub fn reanalyze(&mut self) {
        // Use direct field access to enable split borrows (tabs + registry).
        let Some(WorkspaceTab::File { file, analysis }) = self.tabs.get_mut(self.active_tab) else {
            return;
        };
        let patched =
            tinkerspark_core_patch::PatchedView::new(&*file.source, file.patches.patches());
        match self.registry.auto_analyze(&file.handle, &patched) {
            Some(Ok(report)) => {
                let node_count = report.root_nodes.len();
                let armored = has_decoded_ranges(&report);
                *analysis = Some(AnalysisState {
                    report,
                    stale: false,
                    armored,
                    selected_node: None,
                    selected_range: None,
                });
                self.status_message = Some(format!("Re-analyzed: {node_count} nodes"));
            }
            Some(Err(e)) => {
                self.status_message = Some(format!("Re-analysis failed: {e}"));
            }
            None => {
                *analysis = None;
            }
        }
    }

    /// Open two files for comparison as a new diff tab.
    pub fn open_diff(&mut self, left_path: &Path, right_path: &Path) {
        let left = match open_as_openfile(left_path) {
            Ok(f) => f,
            Err(e) => {
                self.status_message = Some(format!("Left file error: {e}"));
                return;
            }
        };
        let right = match open_as_openfile(right_path) {
            Ok(f) => f,
            Err(e) => {
                self.status_message = Some(format!("Right file error: {e}"));
                return;
            }
        };

        let config = tinkerspark_core_diff::DiffConfig::default();
        let result =
            match tinkerspark_core_diff::compute_diff(&*left.source, &*right.source, &config) {
                Ok(r) => r,
                Err(e) => {
                    self.status_message = Some(format!("Diff failed: {e}"));
                    return;
                }
            };
        let navigator = DiffNavigator::new(&result);

        let left_name = left.handle.path.display().to_string();
        let right_name = right.handle.path.display().to_string();
        let change_count = result.change_count();

        self.tabs.push(WorkspaceTab::Diff(DiffSession {
            left,
            right,
            result,
            navigator,
            sync_scroll: true,
            scroll_authority: ScrollAuthority::Left,
            last_merged_side: None,
            merged_regions: Vec::new(),
        }));
        self.active_tab = self.tabs.len() - 1;
        self.status_message = Some(format!(
            "Comparing: {} vs {} ({} changes)",
            left_name, right_name, change_count
        ));
    }
}

fn ranges_overlap(a: &ByteRange, b: &ByteRange) -> bool {
    a.offset() < b.end() && b.offset() < a.end()
}

/// Build the analyzer registry with the given generic-fallback sensitivity.
/// Dedicated analyzers always rank above the generic fallback by virtue of
/// returning higher confidence levels.
fn build_registry(generic_sensitivity: Sensitivity) -> AnalyzerRegistry {
    let mut registry = AnalyzerRegistry::new();
    registry.register(Box::new(tinkerspark_format_openpgp::OpenPgpAnalyzer));
    registry.register(Box::new(tinkerspark_format_x509::X509Analyzer));
    registry.register(Box::new(tinkerspark_format_ssh::SshAnalyzer));
    registry.register(Box::new(tinkerspark_format_age::AgeAnalyzer));
    registry.register(Box::new(tinkerspark_format_jwk::JwkAnalyzer));
    registry.register(Box::new(
        tinkerspark_format_generic::GenericAnalyzer::with_mode(generic_sensitivity),
    ));
    registry
}

fn open_as_openfile(path: &Path) -> Result<OpenFile, String> {
    let (source, handle, backend) =
        tinkerspark_core_bytes::open_file(path).map_err(|e| e.to_string())?;
    let file_len = source.len();
    Ok(OpenFile {
        handle,
        source,
        backend,
        hex: HexViewState::new(file_len),
        patches: PatchHistory::new(file_len),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tinkerspark_core_bytes::MemoryByteSource;
    use tinkerspark_core_types::{DetectedKind, FileId};

    /// Push a synthetic in-memory file tab so we can exercise reanalysis
    /// without touching disk.
    fn push_synthetic_file(state: &mut AppState, data: Vec<u8>) {
        let file_len = data.len() as u64;
        let handle = FileHandle {
            id: FileId::new(),
            path: PathBuf::from("synthetic.bin"),
            size: file_len,
            kind: DetectedKind::Binary,
        };
        let source: Box<dyn ByteSource> = Box::new(MemoryByteSource::new(data));
        let analysis_result = state.registry.auto_analyze(&handle, &*source);
        let analysis = match analysis_result {
            Some(Ok(report)) => Some(AnalysisState {
                report,
                stale: false,
                armored: false,
                selected_node: None,
                selected_range: None,
            }),
            _ => None,
        };
        let file = OpenFile {
            handle,
            source,
            backend: BackendKind::Buffered,
            hex: HexViewState::new(file_len),
            patches: PatchHistory::new(file_len),
        };
        state.tabs.push(WorkspaceTab::File { file, analysis });
        state.active_tab = state.tabs.len() - 1;
    }

    fn overview_sensitivity(state: &AppState) -> Option<String> {
        state
            .active_analysis()?
            .report
            .root_nodes
            .iter()
            .find(|n| n.kind == "overview")?
            .fields
            .iter()
            .find(|f| f.name == "Sensitivity")
            .map(|f| f.value.clone())
    }

    #[test]
    fn session_round_trip_restores_sensitivity() {
        let mut session = SessionState::default();
        session.generic_sensitivity = Some("Aggressive".into());
        let state = AppState::with_session(session);
        assert_eq!(state.generic_sensitivity, Sensitivity::Aggressive);
    }

    #[test]
    fn missing_session_field_defaults_to_balanced() {
        let state = AppState::with_session(SessionState::default());
        assert_eq!(state.generic_sensitivity, Sensitivity::Balanced);
    }

    #[test]
    fn switching_sensitivity_reanalyzes_active_file_and_updates_overview() {
        let mut state = AppState::with_session(SessionState::default());
        // Start with a known mode that produces an overview field of "Balanced".
        push_synthetic_file(&mut state, vec![0x42; 64]);
        assert_eq!(overview_sensitivity(&state).as_deref(), Some("Balanced"));

        // Switching modes must rebuild the registry, rerun analysis, and the
        // new mode must show up in the overview field surfaced by the analyzer.
        state.set_generic_sensitivity(Sensitivity::Aggressive);
        assert_eq!(state.generic_sensitivity, Sensitivity::Aggressive);
        assert_eq!(overview_sensitivity(&state).as_deref(), Some("Aggressive"));

        state.set_generic_sensitivity(Sensitivity::Conservative);
        assert_eq!(
            overview_sensitivity(&state).as_deref(),
            Some("Conservative")
        );

        // The session mirror must follow the live state so on_exit persists it.
        assert_eq!(
            state.session.generic_sensitivity.as_deref(),
            Some("Conservative")
        );
    }

    #[test]
    fn setting_same_sensitivity_is_a_noop() {
        let mut state = AppState::with_session(SessionState::default());
        push_synthetic_file(&mut state, vec![0x42; 64]);
        let initial_status = state.status_message.clone();
        state.set_generic_sensitivity(Sensitivity::Balanced);
        // No change → no status message bump from set_generic_sensitivity.
        assert_eq!(state.status_message, initial_status);
    }
}
