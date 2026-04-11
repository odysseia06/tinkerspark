use egui::Ui;
use serde::{Deserialize, Serialize};

use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_patch::PatchedView;

use crate::state::AppState;

/// Identifies which pane is being displayed in a dock tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PaneKind {
    Hex,
    Structure,
    Metadata,
    Patches,
    Diagnostics,
    Bookmarks,
}

impl PaneKind {
    pub fn title(&self) -> &'static str {
        match self {
            PaneKind::Hex => "Editor",
            PaneKind::Structure => "Structure",
            PaneKind::Metadata => "Metadata",
            PaneKind::Patches => "Patches",
            PaneKind::Diagnostics => "Diagnostics",
            PaneKind::Bookmarks => "Bookmarks",
        }
    }
}

pub fn render_pane(ui: &mut Ui, kind: &PaneKind, state: &mut AppState) {
    match kind {
        PaneKind::Hex => crate::hex_pane::render_hex_pane(ui, state),
        PaneKind::Metadata => render_metadata(ui, state),
        PaneKind::Structure => render_structure_pane(ui, state),
        PaneKind::Patches => render_patches_pane(ui, state),
        PaneKind::Diagnostics => render_diagnostics_pane(ui, state),
        PaneKind::Bookmarks => render_bookmarks_pane(ui, state),
    }
}

fn render_metadata(ui: &mut Ui, state: &AppState) {
    let Some(file) = state.active_file() else {
        render_empty_state(ui, "No file open. Use File > Open to inspect a file.");
        return;
    };

    ui.heading("File Metadata");
    ui.separator();

    egui::Grid::new("metadata_grid")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.strong("Path:");
            ui.label(file.handle.path.display().to_string());
            ui.end_row();

            ui.strong("Size:");
            ui.label(format_size(file.handle.size));
            ui.end_row();

            ui.strong("Kind:");
            ui.label(file.handle.kind.to_string());
            ui.end_row();

            ui.strong("Backend:");
            ui.label(file.backend.to_string());
            ui.end_row();

            if file.patches.is_dirty() {
                ui.strong("Status:");
                ui.label(format!("Modified ({} patches)", file.patches.patch_count()));
                ui.end_row();
            }
        });

    // Selection info.
    if let Some(sel) = &file.hex.selection {
        ui.add_space(12.0);
        ui.heading("Selection");
        ui.separator();

        egui::Grid::new("selection_grid")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.strong("Start:");
                ui.label(format!("0x{:X} ({})", sel.start(), sel.start()));
                ui.end_row();

                ui.strong("End:");
                ui.label(format!(
                    "0x{:X} ({})",
                    sel.end_inclusive(),
                    sel.end_inclusive()
                ));
                ui.end_row();

                ui.strong("Length:");
                ui.label(format!("{} bytes", sel.len()));
                ui.end_row();
            });

        let sel_range = tinkerspark_core_types::ByteRange::new(sel.start(), sel.len());
        let patched = PatchedView::new(&*file.source, file.patches.patches());
        if let Ok(sel_bytes) = patched.read_range(sel_range) {
            let meta = tinkerspark_core_hexview::SelectionMeta::from_bytes(sel, &sel_bytes);

            egui::Grid::new("selection_values_grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("Hex:");
                    ui.label(&meta.hex_preview);
                    ui.end_row();

                    ui.strong("ASCII:");
                    ui.label(&meta.ascii_preview);
                    ui.end_row();

                    if let Some(v) = meta.u8_val {
                        ui.strong("u8:");
                        ui.label(format!("{v} (0x{v:02X})"));
                        ui.end_row();
                    }
                    if let Some(v) = meta.u16_le {
                        ui.strong("u16 LE:");
                        ui.label(format!("{v} (0x{v:04X})"));
                        ui.end_row();
                    }
                    if let Some(v) = meta.u16_be {
                        ui.strong("u16 BE:");
                        ui.label(format!("{v} (0x{v:04X})"));
                        ui.end_row();
                    }
                    if let Some(v) = meta.u32_le {
                        ui.strong("u32 LE:");
                        ui.label(format!("{v} (0x{v:08X})"));
                        ui.end_row();
                    }
                    if let Some(v) = meta.u32_be {
                        ui.strong("u32 BE:");
                        ui.label(format!("{v} (0x{v:08X})"));
                        ui.end_row();
                    }
                    if let Some(v) = meta.u64_le {
                        ui.strong("u64 LE:");
                        ui.label(format!("{v}"));
                        ui.end_row();
                    }
                    if let Some(v) = meta.u64_be {
                        ui.strong("u64 BE:");
                        ui.label(format!("{v}"));
                        ui.end_row();
                    }
                });
        }
    } else {
        ui.add_space(12.0);
        ui.label(format!("Cursor: 0x{:X}", file.hex.cursor));
    }
}

fn render_patches_pane(ui: &mut Ui, state: &mut AppState) {
    let Some(file) = state.active_file_mut() else {
        ui.heading("Patches");
        ui.separator();
        ui.label("No file open.");
        return;
    };

    ui.heading("Patches");
    ui.separator();

    let mut bytes_changed = false;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(file.patches.can_undo(), egui::Button::new("Undo"))
            .clicked()
        {
            file.patches.undo();
            bytes_changed = true;
        }
        if ui
            .add_enabled(file.patches.can_redo(), egui::Button::new("Redo"))
            .clicked()
        {
            file.patches.redo();
            bytes_changed = true;
        }
        if ui
            .add_enabled(file.patches.is_dirty(), egui::Button::new("Revert All"))
            .clicked()
        {
            file.patches.revert_all();
            bytes_changed = true;
        }
    });

    ui.separator();

    if file.patches.patches().is_empty() {
        ui.label("No patches applied.");
    } else {
        ui.label(format!("{} patch(es):", file.patches.patch_count()));
        ui.add_space(4.0);

        egui::ScrollArea::vertical()
            .id_salt("patch_list")
            .show(ui, |ui| {
                for (i, patch) in file.patches.patches().patches().iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "#{}: 0x{:X}..0x{:X} ({} bytes) \"{}\"",
                            i + 1,
                            patch.range.offset(),
                            patch.range.end(),
                            patch.range.length(),
                            patch.label,
                        ));
                        let preview: String = patch
                            .replacement
                            .iter()
                            .take(8)
                            .map(|b| format!("{b:02X}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        if patch.replacement.len() > 8 {
                            ui.label(format!("[{preview} ...]"));
                        } else {
                            ui.label(format!("[{preview}]"));
                        }
                    });
                }
            });
    }

    if bytes_changed {
        state.mark_analysis_stale();
    }
}

fn render_structure_pane(ui: &mut Ui, state: &mut AppState) {
    if state.active_file().is_none() {
        render_empty_state(ui, "No file open.");
        return;
    }

    ui.heading("Structure");
    ui.separator();

    let Some(analysis) = state.active_analysis() else {
        ui.label("No analysis available for this file type.");
        return;
    };

    let mut wants_reanalyze = false;
    if let Some(label) = analysis.freshness.short_label() {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(label).color(egui::Color32::from_rgb(255, 180, 50)));
            if ui.button("Re-analyze").clicked() {
                wants_reanalyze = true;
            }
        });
        ui.separator();
    }

    if wants_reanalyze {
        state.reanalyze();
        return;
    }

    let report = &analysis.report;

    if report.root_nodes.is_empty() {
        ui.label("No structure found.");
        return;
    }

    let mut clicked_node: Option<(
        tinkerspark_core_types::NodeId,
        tinkerspark_core_types::ByteRange,
    )> = None;
    let selected = analysis.selected_node;

    egui::ScrollArea::vertical()
        .id_salt("structure_tree")
        .show(ui, |ui| {
            for node in &report.root_nodes {
                render_analysis_node(ui, node, selected, &mut clicked_node);
            }
        });

    if let Some((node_id, range)) = clicked_node {
        state.apply_structure_click(node_id, range);
    }
}

fn render_analysis_node(
    ui: &mut Ui,
    node: &tinkerspark_core_analyze::AnalysisNode,
    selected: Option<tinkerspark_core_types::NodeId>,
    clicked: &mut Option<(
        tinkerspark_core_types::NodeId,
        tinkerspark_core_types::ByteRange,
    )>,
) {
    let is_selected = selected == Some(node.id);
    let header_text = format!(
        "{} [0x{:X}..0x{:X}]",
        node.label,
        node.range.offset(),
        node.range.end(),
    );

    let id = ui.make_persistent_id(format!("node_{:?}", node.id));

    egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false)
        .show_header(ui, |ui| {
            let resp = ui.selectable_label(is_selected, &header_text);
            if resp.clicked() {
                *clicked = Some((node.id, node.range));
            }
        })
        .body(|ui| {
            if !node.fields.is_empty() {
                egui::Grid::new(format!("fields_{:?}", node.id))
                    .num_columns(2)
                    .spacing([8.0, 2.0])
                    .show(ui, |ui| {
                        for field in &node.fields {
                            ui.label(egui::RichText::new(&field.name).color(egui::Color32::GRAY));
                            // Fields with a byte range become clickable: a
                            // click feeds (parent_node_id, field.range) into
                            // the same dispatch as a node click, so the hex
                            // view jumps to the exact field bytes.
                            if let Some(range) = field.range {
                                let resp = ui.selectable_label(false, &field.value);
                                if resp.clicked() {
                                    *clicked = Some((node.id, range));
                                }
                            } else {
                                ui.label(&field.value);
                            }
                            ui.end_row();
                        }
                    });
            }

            for diag in &node.diagnostics {
                let color = match diag.severity {
                    tinkerspark_core_types::Severity::Error => egui::Color32::from_rgb(255, 80, 80),
                    tinkerspark_core_types::Severity::Warning => {
                        egui::Color32::from_rgb(255, 180, 50)
                    }
                    tinkerspark_core_types::Severity::Info => {
                        egui::Color32::from_rgb(100, 180, 255)
                    }
                };
                ui.label(egui::RichText::new(&diag.message).color(color));
            }

            for child in &node.children {
                render_analysis_node(ui, child, selected, clicked);
            }
        });
}

fn render_diagnostics_pane(ui: &mut Ui, state: &AppState) {
    ui.heading("Diagnostics");
    ui.separator();

    let Some(analysis) = state.active_analysis() else {
        ui.label("No analysis active.");
        return;
    };

    if let Some(detail) = analysis.freshness.detail() {
        ui.label(egui::RichText::new(detail).color(egui::Color32::from_rgb(255, 180, 50)));
        ui.separator();
    }

    let report = &analysis.report;

    if report.diagnostics.is_empty() {
        let node_diags: Vec<_> = report
            .root_nodes
            .iter()
            .flat_map(|n| n.diagnostics.iter())
            .collect();

        if node_diags.is_empty() {
            ui.label("No diagnostics.");
        } else {
            for diag in node_diags {
                render_diagnostic(ui, diag);
            }
        }
    } else {
        for diag in &report.diagnostics {
            render_diagnostic(ui, diag);
        }
        for node in &report.root_nodes {
            for diag in &node.diagnostics {
                render_diagnostic(ui, diag);
            }
        }
    }
}

fn render_diagnostic(ui: &mut Ui, diag: &tinkerspark_core_types::Diagnostic) {
    let (icon, color) = match diag.severity {
        tinkerspark_core_types::Severity::Error => ("E", egui::Color32::from_rgb(255, 80, 80)),
        tinkerspark_core_types::Severity::Warning => ("W", egui::Color32::from_rgb(255, 180, 50)),
        tinkerspark_core_types::Severity::Info => ("I", egui::Color32::from_rgb(100, 180, 255)),
    };
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(icon).color(color).strong());
        ui.label(&diag.message);
        if let Some(range) = &diag.range {
            ui.label(
                egui::RichText::new(format!("@ 0x{:X}", range.offset())).color(egui::Color32::GRAY),
            );
        }
    });
}

fn render_bookmarks_pane(ui: &mut Ui, state: &mut AppState) {
    ui.heading("Bookmarks");
    ui.separator();

    let Some(file) = state.active_file() else {
        ui.label("No file open.");
        return;
    };
    let file_path = file.handle.path.clone();
    let cursor = file.hex.cursor;
    let bookmarks: Vec<_> = state
        .session
        .bookmarks_for_file(&file_path)
        .into_iter()
        .cloned()
        .collect();

    ui.horizontal(|ui| {
        if ui.button("Add at cursor  Ctrl+B").clicked() {
            let label = format!("0x{cursor:X}");
            state.session.add_bookmark(file_path.clone(), cursor, label);
        }
    });
    ui.separator();

    if bookmarks.is_empty() {
        ui.label("No bookmarks for this file.");
        return;
    }

    let mut jump_to = None;
    let mut remove = None;

    egui::ScrollArea::vertical()
        .id_salt("bookmark_list")
        .show(ui, |ui| {
            for bm in &bookmarks {
                ui.horizontal(|ui| {
                    if ui
                        .button(format!("0x{:X}", bm.offset))
                        .on_hover_text(&bm.label)
                        .clicked()
                    {
                        jump_to = Some(bm.offset);
                    }
                    ui.label(&bm.label);
                    if ui.small_button("x").clicked() {
                        remove = Some(bm.offset);
                    }
                });
            }
        });

    if let Some(offset) = jump_to {
        if let Some(file) = state.active_file_mut() {
            file.hex.jump_to(offset);
        }
    }
    if let Some(offset) = remove {
        state.session.remove_bookmark(&file_path, offset);
    }
}

fn render_empty_state(ui: &mut Ui, message: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        ui.heading("Tinkerspark");
        ui.add_space(8.0);
        ui.label(message);
    });
}

fn format_size(bytes: u64) -> String {
    if bytes == 0 {
        return "0 bytes".to_string();
    }
    let units = ["bytes", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < units.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{bytes} bytes")
    } else {
        format!("{size:.1} {}", units[unit_idx])
    }
}
