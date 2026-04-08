use egui_dock::{DockArea, DockState, NodeIndex, Style};

use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_hexview::parse_hex_pattern;
use tinkerspark_core_types::ByteRange;

use crate::panes::{self, PaneKind};
use crate::state::AppState;

const ALL_PANES: &[PaneKind] = &[
    PaneKind::Hex,
    PaneKind::Structure,
    PaneKind::Metadata,
    PaneKind::Patches,
    PaneKind::Diagnostics,
    PaneKind::Bookmarks,
];

pub struct TinkersparkApp {
    state: AppState,
    dock_state: DockState<PaneKind>,
}

impl TinkersparkApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut state = AppState::new();

        // Restore dock layout from previous session, or use default.
        let dock_state = state
            .session
            .dock_layout
            .as_ref()
            .and_then(|v| serde_json::from_value::<DockState<PaneKind>>(v.clone()).ok())
            .unwrap_or_else(build_default_layout);

        // Restore open file tabs from previous session.
        let files_to_restore = if !state.session.last_open_files.is_empty() {
            state.session.last_open_files.clone()
        } else {
            // Fall back to legacy single-file field for old session files.
            state.session.last_open_file.clone().into_iter().collect()
        };
        for path in &files_to_restore {
            if path.exists() {
                state.open(path);
            }
        }
        // Restore active tab index, clamped to valid range.
        let saved_active = state.session.last_active_tab;
        if !state.tabs.is_empty() {
            state.active_tab = saved_active.min(state.tabs.len() - 1);
        }

        Self { state, dock_state }
    }
}

fn build_default_layout() -> DockState<PaneKind> {
    let mut dock = DockState::new(vec![PaneKind::Hex]);

    let surface = dock.main_surface_mut();
    let [_left, right] = surface.split_right(NodeIndex::root(), 0.65, vec![PaneKind::Metadata]);
    surface.split_below(right, 0.5, vec![PaneKind::Structure]);

    let [_main, _bottom] = surface.split_below(
        NodeIndex::root(),
        0.75,
        vec![PaneKind::Patches, PaneKind::Diagnostics],
    );

    dock
}

fn dock_contains(dock: &DockState<PaneKind>, kind: &PaneKind) -> bool {
    dock.iter_all_tabs().any(|(_, tab)| tab == kind)
}

impl eframe::App for TinkersparkApp {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        let layout = serde_json::to_value(&self.dock_state).ok();
        self.state.save_session_with_layout(layout);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let is_diff = self.state.is_diff_active();

        // Update window title with dirty indicator.
        let dirty = self.state.active_tab().is_some_and(|tab| tab.is_dirty());
        let tab_name = self
            .state
            .active_tab()
            .map(|t| t.name())
            .unwrap_or_default();

        let title = if dirty {
            format!("Tinkerspark - {tab_name} *")
        } else if !tab_name.is_empty() {
            format!("Tinkerspark - {tab_name}")
        } else {
            "Tinkerspark".to_string()
        };
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));

        // Global keyboard shortcuts.
        handle_shortcuts(ctx, &mut self.state);

        // Top menu bar.
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open...  Ctrl+O").clicked() {
                        ui.close_menu();
                        open_file_dialog(&mut self.state);
                    }

                    if ui.button("Compare...").clicked() {
                        ui.close_menu();
                        compare_file_dialog(&mut self.state);
                    }

                    if is_diff {
                        let diff_dirty = self.state.active_diff().is_some_and(|d| d.is_dirty());
                        let left_dirty = self
                            .state
                            .active_diff()
                            .is_some_and(|d| d.left.patches.is_dirty());
                        let right_dirty = self
                            .state
                            .active_diff()
                            .is_some_and(|d| d.right.patches.is_dirty());

                        if ui
                            .add_enabled(left_dirty, egui::Button::new("Save Left As..."))
                            .clicked()
                        {
                            ui.close_menu();
                            save_diff_side_dialog(&mut self.state, crate::state::DiffSide::Left);
                        }
                        if ui
                            .add_enabled(right_dirty, egui::Button::new("Save Right As..."))
                            .clicked()
                        {
                            ui.close_menu();
                            save_diff_side_dialog(&mut self.state, crate::state::DiffSide::Right);
                        }
                        if ui
                            .add_enabled(diff_dirty, egui::Button::new("Save Both As..."))
                            .clicked()
                        {
                            ui.close_menu();
                            if left_dirty {
                                save_diff_side_dialog(
                                    &mut self.state,
                                    crate::state::DiffSide::Left,
                                );
                            }
                            if right_dirty {
                                save_diff_side_dialog(
                                    &mut self.state,
                                    crate::state::DiffSide::Right,
                                );
                            }
                        }

                        ui.separator();
                        if ui.button("Export Diff Report...").clicked() {
                            ui.close_menu();
                            export_diff_report(&mut self.state);
                        }
                    } else {
                        let can_save = self
                            .state
                            .active_file()
                            .is_some_and(|f| f.patches.is_dirty());
                        if ui
                            .add_enabled(
                                can_save,
                                egui::Button::new("Save Patched Copy...  Ctrl+S"),
                            )
                            .clicked()
                        {
                            ui.close_menu();
                            save_patched_copy_dialog(&mut self.state);
                        }
                    }

                    // Close tab.
                    if !self.state.tabs.is_empty() {
                        ui.separator();
                        if ui.button("Close Tab  Ctrl+W").clicked() {
                            ui.close_menu();
                            self.state.request_close_tab(self.state.active_tab);
                        }
                    }

                    // Recent files submenu.
                    if !self.state.session.recent_files.is_empty() {
                        ui.separator();
                        ui.menu_button("Recent Files", |ui| {
                            let recents: Vec<_> = self
                                .state
                                .session
                                .recent_files
                                .iter()
                                .map(|r| r.path.clone())
                                .collect();
                            for path in &recents {
                                let label = path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| path.display().to_string());
                                if ui
                                    .button(&label)
                                    .on_hover_text(path.display().to_string())
                                    .clicked()
                                {
                                    ui.close_menu();
                                    self.state.open(path);
                                }
                            }
                        });
                    }

                    ui.separator();
                    if ui.button("Quit  Ctrl+Q").clicked() {
                        let layout = serde_json::to_value(&self.dock_state).ok();
                        self.state.save_session_with_layout(layout);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Edit", |ui| {
                    if is_diff {
                        let can_undo = self.state.active_diff().is_some_and(|d| {
                            d.left.patches.can_undo() || d.right.patches.can_undo()
                        });
                        let can_redo = self.state.active_diff().is_some_and(|d| {
                            d.left.patches.can_redo() || d.right.patches.can_redo()
                        });
                        let diff_dirty = self.state.active_diff().is_some_and(|d| d.is_dirty());

                        if ui
                            .add_enabled(can_undo, egui::Button::new("Undo  Ctrl+Z"))
                            .on_hover_text("Undo last merge")
                            .clicked()
                        {
                            diff_undo(&mut self.state);
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(can_redo, egui::Button::new("Redo  Ctrl+Y"))
                            .on_hover_text("Redo last merge")
                            .clicked()
                        {
                            diff_redo(&mut self.state);
                            ui.close_menu();
                        }

                        ui.separator();

                        if ui
                            .add_enabled(diff_dirty, egui::Button::new("Revert All"))
                            .clicked()
                        {
                            if let Some(d) = self.state.active_diff_mut() {
                                d.revert_side(crate::state::DiffSide::Left);
                                d.revert_side(crate::state::DiffSide::Right);
                            }
                            ui.close_menu();
                        }
                    } else {
                        let has_selection = self
                            .state
                            .active_file()
                            .is_some_and(|f| f.hex.selection.is_some());
                        let can_undo = self
                            .state
                            .active_file()
                            .is_some_and(|f| f.patches.can_undo());
                        let can_redo = self
                            .state
                            .active_file()
                            .is_some_and(|f| f.patches.can_redo());

                        if ui
                            .add_enabled(
                                has_selection,
                                egui::Button::new("Edit Selection...  Ctrl+E"),
                            )
                            .clicked()
                        {
                            ui.close_menu();
                            self.state.show_edit_dialog = true;
                            self.state.edit_dialog_tab = self.state.active_tab;
                            prefill_edit_input(&mut self.state);
                        }

                        ui.separator();

                        if ui
                            .add_enabled(can_undo, egui::Button::new("Undo  Ctrl+Z"))
                            .clicked()
                        {
                            if let Some(file) = self.state.active_file_mut() {
                                file.patches.undo();
                            }
                            self.state.mark_analysis_stale();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(can_redo, egui::Button::new("Redo  Ctrl+Y"))
                            .clicked()
                        {
                            if let Some(file) = self.state.active_file_mut() {
                                file.patches.redo();
                            }
                            self.state.mark_analysis_stale();
                            ui.close_menu();
                        }

                        ui.separator();

                        if ui
                            .add_enabled(
                                self.state
                                    .active_file()
                                    .is_some_and(|f| f.patches.is_dirty()),
                                egui::Button::new("Revert All"),
                            )
                            .clicked()
                        {
                            if let Some(file) = self.state.active_file_mut() {
                                file.patches.revert_all();
                            }
                            self.state.mark_analysis_stale();
                            ui.close_menu();
                        }
                    }
                });

                ui.menu_button("View", |ui| {
                    for pane in ALL_PANES {
                        let open = dock_contains(&self.dock_state, pane);
                        if ui
                            .add_enabled(!open, egui::Button::new(pane.title()))
                            .clicked()
                        {
                            self.dock_state.push_to_focused_leaf(*pane);
                            ui.close_menu();
                        }
                    }
                    ui.separator();
                    if ui.button("Reset Layout").clicked() {
                        self.dock_state = build_default_layout();
                        ui.close_menu();
                    }
                    ui.separator();
                    let current_mode = self.state.generic_sensitivity;
                    ui.menu_button(
                        format!("Generic Sensitivity: {}", current_mode.label()),
                        |ui| {
                            for mode in tinkerspark_format_generic::Sensitivity::all() {
                                let selected = mode == current_mode;
                                if ui
                                    .add(egui::SelectableLabel::new(selected, mode.label()))
                                    .clicked()
                                {
                                    self.state.set_generic_sensitivity(mode);
                                    ui.close_menu();
                                }
                            }
                        },
                    );
                    ui.separator();
                    let is_dark = ctx.style().visuals.dark_mode;
                    if ui
                        .button(if is_dark { "Light Theme" } else { "Dark Theme" })
                        .clicked()
                    {
                        if is_dark {
                            ctx.set_visuals(egui::Visuals::light());
                        } else {
                            ctx.set_visuals(egui::Visuals::dark());
                        }
                        ui.close_menu();
                    }
                });
            });
        });

        // Status bar.
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(msg) = &self.state.status_message {
                    ui.label(msg);
                } else {
                    ui.label("Ready");
                }
                if dirty {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new("Modified")
                                .color(egui::Color32::from_rgb(255, 180, 50)),
                        );
                    });
                }
            });
        });

        // Command palette.
        render_command_palette(ctx, &mut self.state, &mut self.dock_state);

        // Edit dialog (modal-style window) — only for file tabs.
        if !is_diff {
            render_edit_dialog(ctx, &mut self.state);
        }

        // Close-tab confirmation dialog for dirty tabs.
        render_close_confirm_dialog(ctx, &mut self.state);

        // Synchronized scroll propagation for diff tabs.
        if let Some(diff) = self.state.active_diff_mut() {
            if diff.sync_scroll {
                use crate::state::ScrollAuthority;
                match diff.scroll_authority {
                    ScrollAuthority::Left => {
                        diff.right.hex.scroll_offset = diff.left.hex.scroll_offset;
                    }
                    ScrollAuthority::Right => {
                        diff.left.hex.scroll_offset = diff.right.hex.scroll_offset;
                    }
                }
            }
        }

        // Main dock area.
        DockArea::new(&mut self.dock_state)
            .style(Style::from_egui(ctx.style().as_ref()))
            .show(
                ctx,
                &mut PaneViewer {
                    state: &mut self.state,
                },
            );

        // Track window size for session restore.
        let rect = ctx.input(|i| i.screen_rect());
        self.state.session.window.width = rect.width();
        self.state.session.window.height = rect.height();
    }
}

struct PaneViewer<'a> {
    state: &'a mut AppState,
}

impl egui_dock::TabViewer for PaneViewer<'_> {
    type Tab = PaneKind;

    fn title(&mut self, tab: &mut Self::Tab) -> egui::WidgetText {
        tab.title().into()
    }

    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut Self::Tab) {
        panes::render_pane(ui, tab, self.state);
    }
}

fn open_file_dialog(state: &mut AppState) {
    let file = rfd::FileDialog::new()
        .set_title("Open File")
        .add_filter("All Files", &["*"])
        .add_filter(
            "OpenPGP",
            &["pgp", "gpg", "asc", "sig", "key", "pub", "sec"],
        )
        .pick_file();

    if let Some(path) = file {
        state.open(&path);
    }
}

fn compare_file_dialog(state: &mut AppState) {
    let left = rfd::FileDialog::new()
        .set_title("Select Left File (original)")
        .add_filter("All Files", &["*"])
        .pick_file();

    let Some(left_path) = left else {
        return;
    };

    let right = rfd::FileDialog::new()
        .set_title("Select Right File (modified)")
        .add_filter("All Files", &["*"])
        .pick_file();

    let Some(right_path) = right else {
        return;
    };

    state.open_diff(&left_path, &right_path);
}

fn save_patched_copy_dialog(state: &mut AppState) {
    let Some(file) = state.active_file() else {
        return;
    };

    let target = rfd::FileDialog::new()
        .set_title("Save Patched Copy")
        .add_filter("All Files", &["*"])
        .save_file();

    let Some(target_path) = target else {
        return;
    };

    match tinkerspark_infra_io::save_patched_copy(
        &*file.source,
        file.patches.patches(),
        &file.handle.path,
        &target_path,
    ) {
        Ok(()) => {
            state.status_message = Some(format!("Saved to: {}", target_path.display()));
        }
        Err(e) => {
            state.status_message = Some(format!("Save failed: {e}"));
        }
    }
}

fn save_diff_side_dialog(state: &mut AppState, side: crate::state::DiffSide) {
    let Some(diff) = state.active_diff() else {
        return;
    };

    let file = match side {
        crate::state::DiffSide::Left => &diff.left,
        crate::state::DiffSide::Right => &diff.right,
    };
    let side_label = match side {
        crate::state::DiffSide::Left => "Left",
        crate::state::DiffSide::Right => "Right",
    };

    let target = rfd::FileDialog::new()
        .set_title(&format!("Save {side_label} As"))
        .add_filter("All Files", &["*"])
        .save_file();

    let Some(target_path) = target else {
        return;
    };

    match tinkerspark_infra_io::save_patched_copy(
        &*file.source,
        file.patches.patches(),
        &file.handle.path,
        &target_path,
    ) {
        Ok(()) => {
            state.status_message =
                Some(format!("{side_label} saved to: {}", target_path.display()));
        }
        Err(e) => {
            state.status_message = Some(format!("{side_label} save failed: {e}"));
        }
    }
}

fn diff_undo(state: &mut AppState) {
    let Some(diff) = state.active_diff_mut() else {
        return;
    };

    let side = diff.last_merged_side.unwrap_or_else(|| {
        if diff.right.patches.can_undo() {
            crate::state::DiffSide::Right
        } else {
            crate::state::DiffSide::Left
        }
    });

    if diff.undo_side(side) {
        let label = match side {
            crate::state::DiffSide::Left => "left",
            crate::state::DiffSide::Right => "right",
        };
        state.status_message = Some(format!("Undo ({label})"));
    }
}

fn diff_redo(state: &mut AppState) {
    let Some(diff) = state.active_diff_mut() else {
        return;
    };

    let side = diff.last_merged_side.unwrap_or_else(|| {
        if diff.right.patches.can_redo() {
            crate::state::DiffSide::Right
        } else {
            crate::state::DiffSide::Left
        }
    });

    if diff.redo_side(side) {
        let label = match side {
            crate::state::DiffSide::Left => "left",
            crate::state::DiffSide::Right => "right",
        };
        state.status_message = Some(format!("Redo ({label})"));
    }
}

fn prefill_edit_input(state: &mut AppState) {
    let Some(file) = state.active_file() else {
        return;
    };
    let Some(sel) = &file.hex.selection else {
        return;
    };

    let sel_range = ByteRange::new(sel.start(), sel.len());
    let patched = tinkerspark_core_patch::PatchedView::new(&*file.source, file.patches.patches());
    if let Ok(bytes) = patched.read_range(sel_range) {
        if state.edit_hex_mode {
            state.edit_input = bytes
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
        } else {
            state.edit_input = String::from_utf8_lossy(&bytes).into_owned();
        }
    }
}

fn render_edit_dialog(ctx: &egui::Context, state: &mut AppState) {
    if !state.show_edit_dialog {
        return;
    }

    // Resolve against the tab the dialog was opened for, not the active tab.
    let target_tab = state.edit_dialog_tab;
    let sel_info = match state.tabs.get(target_tab) {
        Some(crate::state::WorkspaceTab::File { file, .. }) => file
            .hex
            .selection
            .as_ref()
            .map(|sel| (sel.start(), sel.len())),
        _ => None,
    };

    let Some((sel_start, sel_len)) = sel_info else {
        state.show_edit_dialog = false;
        return;
    };

    let mut open = true;
    egui::Window::new("Edit Selection")
        .open(&mut open)
        .resizable(false)
        .collapsible(false)
        .show(ctx, |ui| {
            ui.label(format!(
                "Replacing {} bytes at offset 0x{:X}",
                sel_len, sel_start
            ));
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.radio_value(&mut state.edit_hex_mode, true, "Hex");
                ui.radio_value(&mut state.edit_hex_mode, false, "Text");
            });

            ui.add(
                egui::TextEdit::multiline(&mut state.edit_input)
                    .desired_width(400.0)
                    .desired_rows(3)
                    .hint_text(if state.edit_hex_mode {
                        "FF 00 AB ..."
                    } else {
                        "replacement text..."
                    })
                    .font(egui::TextStyle::Monospace),
            );

            let replacement = if state.edit_hex_mode {
                parse_hex_pattern(&state.edit_input)
            } else {
                let bytes = state.edit_input.as_bytes().to_vec();
                if bytes.is_empty() {
                    None
                } else {
                    Some(bytes)
                }
            };

            let valid = replacement
                .as_ref()
                .is_some_and(|r| r.len() as u64 == sel_len);

            if !valid {
                if let Some(r) = &replacement {
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 100, 100),
                        format!(
                            "Length mismatch: replacement is {} bytes, selection is {} bytes",
                            r.len(),
                            sel_len
                        ),
                    );
                } else if !state.edit_input.is_empty() {
                    ui.colored_label(egui::Color32::from_rgb(255, 100, 100), "Invalid input");
                }
            }

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(valid, egui::Button::new("Apply")).clicked() {
                    if let Some(bytes) = replacement {
                        apply_edit(state, target_tab, sel_start, sel_len, bytes);
                        state.show_edit_dialog = false;
                    }
                }
                if ui.button("Cancel").clicked() {
                    state.show_edit_dialog = false;
                }
            });
        });

    if !open {
        state.show_edit_dialog = false;
    }
}

fn render_close_confirm_dialog(ctx: &egui::Context, state: &mut AppState) {
    let Some(index) = state.pending_close_tab else {
        return;
    };

    // If the tab no longer exists or is no longer dirty, just clear.
    let still_dirty = state.tabs.get(index).is_some_and(|tab| tab.is_dirty());
    if !still_dirty {
        state.pending_close_tab = None;
        return;
    }

    let tab_name = state.tabs[index].name();

    let mut open = true;
    let mut action: Option<bool> = None; // Some(true) = discard, Some(false) = cancel

    egui::Window::new("Unsaved Changes")
        .open(&mut open)
        .resizable(false)
        .collapsible(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.label(format!("\"{tab_name}\" has unsaved changes."));
            ui.label("Closing will discard all patches and merges.");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Discard and Close").clicked() {
                    action = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    action = Some(false);
                }
            });
        });

    match action {
        Some(true) => state.close_tab(index),
        Some(false) => state.pending_close_tab = None,
        None => {
            if !open {
                state.pending_close_tab = None;
            }
        }
    }
}

fn apply_edit(state: &mut AppState, tab_index: usize, offset: u64, len: u64, replacement: Vec<u8>) {
    let Some(crate::state::WorkspaceTab::File { file, .. }) = state.tabs.get_mut(tab_index) else {
        return;
    };

    let range = ByteRange::new(offset, len);
    let label = format!("edit @ 0x{:X} ({} bytes)", offset, len);

    match file.patches.apply(range, replacement, label) {
        Ok(()) => {
            state.status_message = Some(format!("Patch applied at 0x{:X} ({} bytes)", offset, len));
            // Mark analysis stale only if this is the active tab.
            if tab_index == state.active_tab {
                state.mark_analysis_stale();
            }
        }
        Err(e) => {
            state.status_message = Some(format!("Patch error: {e}"));
        }
    }
}

fn render_command_palette(
    ctx: &egui::Context,
    state: &mut AppState,
    dock_state: &mut DockState<PaneKind>,
) {
    if !state.show_command_palette {
        return;
    }

    let commands: Vec<(&str, &str)> = vec![
        ("Open File", "open"),
        ("Compare Files", "compare"),
        ("Save Patched Copy", "save"),
        ("Undo", "undo"),
        ("Redo", "redo"),
        ("Edit Selection", "edit"),
        ("Revert All", "revert"),
        ("Toggle Bookmark", "bookmark"),
        ("Reset Layout", "layout reset"),
        ("Dark Theme", "dark theme"),
        ("Light Theme", "light theme"),
        ("Close Tab", "close tab"),
        ("Quit", "quit exit"),
    ];

    let mut open = true;
    let mut chosen: Option<usize> = None;

    egui::Window::new("Command Palette")
        .open(&mut open)
        .resizable(false)
        .collapsible(false)
        .title_bar(false)
        .anchor(egui::Align2::CENTER_TOP, [0.0, 60.0])
        .fixed_size([400.0, 300.0])
        .show(ctx, |ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut state.command_query)
                    .desired_width(380.0)
                    .hint_text("Type a command..."),
            );
            resp.request_focus();

            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                state.show_command_palette = false;
                return;
            }

            ui.separator();

            let query = state.command_query.to_lowercase();
            let filtered: Vec<_> = commands
                .iter()
                .enumerate()
                .filter(|(_, (name, keywords))| {
                    query.is_empty()
                        || name.to_lowercase().contains(&query)
                        || keywords.contains(query.as_str())
                })
                .collect();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for (i, (name, _)) in &filtered {
                    if ui.selectable_label(false, *name).clicked() {
                        chosen = Some(*i);
                    }
                }
            });

            if ui.input(|i| i.key_pressed(egui::Key::Enter)) && !filtered.is_empty() {
                chosen = Some(filtered[0].0);
            }
        });

    if !open {
        state.show_command_palette = false;
    }

    if let Some(idx) = chosen {
        state.show_command_palette = false;
        state.command_query.clear();
        match idx {
            0 => open_file_dialog(state),
            1 => compare_file_dialog(state),
            2 => save_patched_copy_dialog(state),
            3 => {
                // Undo
                if state.is_diff_active() {
                    diff_undo(state);
                } else if let Some(file) = state.active_file_mut() {
                    if file.patches.can_undo() {
                        file.patches.undo();
                        state.mark_analysis_stale();
                    }
                }
            }
            4 => {
                // Redo
                if state.is_diff_active() {
                    diff_redo(state);
                } else if let Some(file) = state.active_file_mut() {
                    if file.patches.can_redo() {
                        file.patches.redo();
                        state.mark_analysis_stale();
                    }
                }
            }
            5 => {
                // Edit Selection
                state.show_edit_dialog = true;
                state.edit_dialog_tab = state.active_tab;
                prefill_edit_input(state);
            }
            6 => {
                // Revert All
                if let Some(file) = state.active_file_mut() {
                    file.patches.revert_all();
                    state.mark_analysis_stale();
                }
            }
            7 => {
                // Toggle Bookmark
                if let Some(file) = state.active_file() {
                    let offset = file.hex.cursor;
                    let path = file.handle.path.clone();
                    let exists = state
                        .session
                        .bookmarks_for_file(&path)
                        .iter()
                        .any(|b| b.offset == offset);
                    if exists {
                        state.session.remove_bookmark(&path, offset);
                    } else {
                        state
                            .session
                            .add_bookmark(path, offset, format!("0x{offset:X}"));
                    }
                }
            }
            8 => {
                // Reset Layout
                *dock_state = build_default_layout();
            }
            9 => ctx.set_visuals(egui::Visuals::dark()),
            10 => ctx.set_visuals(egui::Visuals::light()),
            11 => {
                // Close Tab
                state.request_close_tab(state.active_tab);
            }
            12 => {
                // Quit
                let layout = serde_json::to_value(&*dock_state).ok();
                state.save_session_with_layout(layout);
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            _ => {}
        }
    }
}

fn export_diff_report(state: &mut AppState) {
    let Some(diff) = state.active_diff() else {
        return;
    };

    let target = rfd::FileDialog::new()
        .set_title("Export Diff Report")
        .add_filter("Text Files", &["txt"])
        .add_filter("All Files", &["*"])
        .save_file();

    let Some(target_path) = target else {
        return;
    };

    let mut report = String::new();
    report.push_str("Tinkerspark Diff Report\n");
    report.push_str(&"=".repeat(60));
    report.push('\n');
    report.push_str(&format!(
        "Left:  {} ({} bytes)\n",
        diff.left.handle.path.display(),
        diff.result.left_len
    ));
    report.push_str(&format!(
        "Right: {} ({} bytes)\n",
        diff.right.handle.path.display(),
        diff.result.right_len
    ));
    report.push_str(&format!("Changes: {}\n", diff.result.change_count()));
    report.push_str(&format!(
        "Left changed:  {} bytes\n",
        diff.result.left_changed_bytes()
    ));
    report.push_str(&format!(
        "Right changed: {} bytes\n",
        diff.result.right_changed_bytes()
    ));
    report.push('\n');

    for (i, change) in diff.result.changes.iter().enumerate() {
        report.push_str(&format!(
            "Change #{}: L 0x{:X}..0x{:X} ({} B) / R 0x{:X}..0x{:X} ({} B)\n",
            i + 1,
            change.left.offset(),
            change.left.end(),
            change.left.length(),
            change.right.offset(),
            change.right.end(),
            change.right.length(),
        ));
    }

    match std::fs::write(&target_path, &report) {
        Ok(()) => {
            state.status_message = Some(format!("Report saved to: {}", target_path.display()));
        }
        Err(e) => {
            state.status_message = Some(format!("Export failed: {e}"));
        }
    }
}

fn handle_shortcuts(ctx: &egui::Context, state: &mut AppState) {
    let is_diff = state.is_diff_active();

    ctx.input_mut(|i| {
        // Ctrl+O: Open file.
        if i.consume_shortcut(&egui::KeyboardShortcut::new(
            egui::Modifiers::COMMAND,
            egui::Key::O,
        )) {
            open_file_dialog(state);
        }

        // Ctrl+W: Close tab.
        if i.consume_shortcut(&egui::KeyboardShortcut::new(
            egui::Modifiers::COMMAND,
            egui::Key::W,
        )) {
            state.request_close_tab(state.active_tab);
        }

        // Ctrl+Q: Quit.
        if i.consume_shortcut(&egui::KeyboardShortcut::new(
            egui::Modifiers::COMMAND,
            egui::Key::Q,
        )) {
            i.events.push(egui::Event::WindowFocused(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        // Ctrl+Z: Undo.
        if i.consume_shortcut(&egui::KeyboardShortcut::new(
            egui::Modifiers::COMMAND,
            egui::Key::Z,
        )) {
            if is_diff {
                diff_undo(state);
            } else if let Some(file) = state.active_file_mut() {
                if file.patches.can_undo() {
                    file.patches.undo();
                    state.mark_analysis_stale();
                }
            }
        }

        // Ctrl+Y: Redo.
        if i.consume_shortcut(&egui::KeyboardShortcut::new(
            egui::Modifiers::COMMAND,
            egui::Key::Y,
        )) {
            if is_diff {
                diff_redo(state);
            } else if let Some(file) = state.active_file_mut() {
                if file.patches.can_redo() {
                    file.patches.redo();
                    state.mark_analysis_stale();
                }
            }
        }

        // Ctrl+S: Save.
        if i.consume_shortcut(&egui::KeyboardShortcut::new(
            egui::Modifiers::COMMAND,
            egui::Key::S,
        )) {
            if is_diff {
                let left_dirty = state
                    .active_diff()
                    .is_some_and(|d| d.left.patches.is_dirty());
                let right_dirty = state
                    .active_diff()
                    .is_some_and(|d| d.right.patches.is_dirty());
                if left_dirty {
                    save_diff_side_dialog(state, crate::state::DiffSide::Left);
                }
                if right_dirty {
                    save_diff_side_dialog(state, crate::state::DiffSide::Right);
                }
            } else {
                let can_save = state.active_file().is_some_and(|f| f.patches.is_dirty());
                if can_save {
                    save_patched_copy_dialog(state);
                }
            }
        }

        if !is_diff {
            // Ctrl+E: Edit selection.
            if i.consume_shortcut(&egui::KeyboardShortcut::new(
                egui::Modifiers::COMMAND,
                egui::Key::E,
            )) {
                let has_selection = state
                    .active_file()
                    .is_some_and(|f| f.hex.selection.is_some());
                if has_selection {
                    state.show_edit_dialog = true;
                    state.edit_dialog_tab = state.active_tab;
                    prefill_edit_input(state);
                }
            }

            // Ctrl+G: Jump to offset.
            if i.consume_shortcut(&egui::KeyboardShortcut::new(
                egui::Modifiers::COMMAND,
                egui::Key::G,
            )) {
                state.status_message = Some("Go to: type offset in toolbar".to_string());
            }

            // Ctrl+B: Toggle bookmark at cursor.
            if i.consume_shortcut(&egui::KeyboardShortcut::new(
                egui::Modifiers::COMMAND,
                egui::Key::B,
            )) {
                if let Some(file) = state.active_file() {
                    let offset = file.hex.cursor;
                    let path = file.handle.path.clone();
                    let exists = state
                        .session
                        .bookmarks_for_file(&path)
                        .iter()
                        .any(|b| b.offset == offset);
                    if exists {
                        state.session.remove_bookmark(&path, offset);
                        state.status_message = Some(format!("Bookmark removed at 0x{offset:X}"));
                    } else {
                        let label = format!("0x{offset:X}");
                        state.session.add_bookmark(path, offset, label);
                        state.status_message = Some(format!("Bookmark added at 0x{offset:X}"));
                    }
                }
            }
        }

        // Ctrl+P: Command palette.
        if i.consume_shortcut(&egui::KeyboardShortcut::new(
            egui::Modifiers::COMMAND,
            egui::Key::P,
        )) {
            state.show_command_palette = !state.show_command_palette;
            state.command_query.clear();
        }
    });
}
