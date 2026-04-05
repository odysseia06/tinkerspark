use egui::{self, Color32, RichText, Ui};

use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_diff::ChangedRange;
use tinkerspark_core_hexview::{
    ascii_char, build_rows, format_hex_byte, format_offset, offset_gutter_chars, visible_range,
    HexRow,
};
use tinkerspark_core_patch::PatchedView;

use crate::state::{DiffSession, MergedRegion};

/// Which side of the diff we're rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSide {
    Left,
    Right,
}

/// Color for bytes that differ between the two files.
const DIFF_BG: Color32 = Color32::from_rgb(80, 40, 40);
const DIFF_FG: Color32 = Color32::from_rgb(255, 120, 120);

/// Color for the currently focused change (from navigator).
const FOCUS_BG: Color32 = Color32::from_rgb(100, 80, 30);
const FOCUS_FG: Color32 = Color32::from_rgb(255, 220, 80);

/// Color for bytes that have been merged (resolved differences).
const MERGED_BG: Color32 = Color32::from_rgb(30, 60, 55);
const MERGED_FG: Color32 = Color32::from_rgb(100, 220, 195);

/// Render an entire diff tab: left/right hex side by side, with summary below.
pub fn render_diff_tab(ui: &mut Ui, diff: &mut DiffSession, status_message: &mut Option<String>) {
    // Summary / controls at the bottom.
    egui::TopBottomPanel::bottom("diff_summary_panel")
        .resizable(true)
        .default_height(180.0)
        .show_inside(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("diff_summary_scroll")
                .show(ui, |ui| {
                    render_diff_summary(ui, diff, status_message);
                });
        });

    // Left/right hex views side by side in the remaining space.
    egui::SidePanel::left("diff_left_panel")
        .resizable(true)
        .default_width(ui.available_width() * 0.5)
        .show_inside(ui, |ui| {
            render_diff_hex_side(ui, diff, DiffSide::Left);
        });

    egui::CentralPanel::default().show_inside(ui, |ui| {
        render_diff_hex_side(ui, diff, DiffSide::Right);
    });
}

/// Render one side of the diff hex view.
fn render_diff_hex_side(ui: &mut Ui, diff: &mut DiffSession, side: DiffSide) {
    let (file, file_label) = match side {
        DiffSide::Left => {
            let label = diff.left.handle.path.display().to_string();
            (&mut diff.left, label)
        }
        DiffSide::Right => {
            let label = diff.right.handle.path.display().to_string();
            (&mut diff.right, label)
        }
    };

    let file_len = file.source.len();

    // File header.
    ui.horizontal(|ui| {
        let side_label = match side {
            DiffSide::Left => "Left:",
            DiffSide::Right => "Right:",
        };
        ui.strong(side_label);
        ui.label(&file_label);
    });
    ui.separator();

    if file_len == 0 {
        ui.label("(empty file)");
        return;
    }

    // Layout metrics.
    let bpr = file.hex.bytes_per_row();
    let mono = egui::TextStyle::Monospace;
    let char_width = ui.fonts(|f| f.glyph_width(&ui.style().text_styles[&mono], '0'));
    let row_height = ui.text_style_height(&mono) + ui.spacing().item_spacing.y;
    let avail = ui.available_size();
    let visible_rows = ((avail.y / row_height) as usize).max(1);

    file.hex.ensure_cursor_visible(visible_rows);
    let range = visible_range(file.hex.scroll_offset, visible_rows, bpr, file_len);

    // Read through the patch overlay so merged bytes are visible.
    let data = if range.length() > 0 {
        let patched = PatchedView::new(&*file.source, file.patches.patches());
        patched.read_range(range).unwrap_or_default().into_owned()
    } else {
        Vec::new()
    };

    let rows = build_rows(range.offset(), &data, bpr);
    let gutter_chars = offset_gutter_chars(file_len);
    let _gutter_px = char_width * gutter_chars as f32 + 8.0;

    // Get diff info for highlighting.
    let changes = &diff.result.changes;
    let focused_idx = diff.navigator.current_index();
    let merged_regions = &diff.merged_regions;

    let mut clicked_offset: Option<u64> = None;

    // Use allocate_rect + child UI instead of ScrollArea so scroll events
    // aren't consumed by a no-op ScrollArea before our manual handler.
    let hex_area = ui.available_rect_before_wrap();
    let hex_response = ui.allocate_rect(hex_area, egui::Sense::hover());

    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(hex_area));
    for row in &rows {
        render_diff_row(
            &mut child,
            row,
            bpr,
            file_len,
            changes,
            focused_idx,
            merged_regions,
            side,
            &mut clicked_offset,
        );
    }

    // Mouse scroll for virtual scrolling.
    if hex_response.hovered() {
        let scroll_delta = ui.input(|i| i.smooth_scroll_delta.y);
        if scroll_delta != 0.0 {
            let scroll_rows = if scroll_delta > 0.0 { -3i64 } else { 3 };
            let bpr64 = bpr as u64;
            let current_row = file.hex.scroll_offset / bpr64;
            let new_row = if scroll_rows < 0 {
                current_row.saturating_sub(scroll_rows.unsigned_abs())
            } else {
                current_row.saturating_add(scroll_rows as u64)
            };
            file.hex.scroll_to_row(new_row);

            // This pane was scrolled — it becomes the authority.
            diff.scroll_authority = match side {
                DiffSide::Left => crate::state::ScrollAuthority::Left,
                DiffSide::Right => crate::state::ScrollAuthority::Right,
            };
        }
    }

    // Navigate to the clicked change (if any).
    if let Some(offset) = clicked_offset {
        let found = diff.result.changes.binary_search_by(|change| {
            let range = match side {
                DiffSide::Left => &change.left,
                DiffSide::Right => &change.right,
            };
            if offset < range.offset() {
                std::cmp::Ordering::Greater
            } else if offset >= range.end() {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        });
        if let Ok(idx) = found {
            diff.navigator.go_to(idx);
        }
    }
}

/// Render a single row of hex with diff highlighting.
fn render_diff_row(
    ui: &mut Ui,
    row: &HexRow,
    bytes_per_row: usize,
    file_len: u64,
    changes: &[ChangedRange],
    focused_idx: Option<usize>,
    merged_regions: &[MergedRegion],
    side: DiffSide,
    clicked_offset: &mut Option<u64>,
) {
    let mono = egui::TextStyle::Monospace;

    ui.horizontal(|ui| {
        // Offset gutter.
        let offset_str = format_offset(row.offset, file_len);
        ui.label(
            RichText::new(&offset_str)
                .text_style(mono.clone())
                .color(Color32::GRAY),
        );
        ui.add_space(8.0);

        // Hex bytes.
        for (i, &byte) in row.bytes.iter().enumerate() {
            let file_offset = row.offset + i as u64;
            let hex = format_hex_byte(byte);
            let hex_str = std::str::from_utf8(&hex).unwrap_or("??");

            let (color, bg) =
                diff_byte_style(file_offset, changes, focused_idx, merged_regions, side);

            let resp = if let Some(bg_color) = bg {
                ui.add(
                    egui::Label::new(
                        RichText::new(hex_str)
                            .text_style(mono.clone())
                            .color(color)
                            .background_color(bg_color),
                    )
                    .sense(egui::Sense::click()),
                )
            } else {
                ui.label(RichText::new(hex_str).text_style(mono.clone()).color(color))
            };

            if resp.clicked() {
                *clicked_offset = Some(file_offset);
            }

            if i + 1 < row.bytes.len() && (i + 1) % 8 == 0 {
                ui.add_space(4.0);
            }
        }

        // Pad remaining columns if row is short.
        let missing = bytes_per_row.saturating_sub(row.bytes.len());
        if missing > 0 {
            let pad: String = "   ".repeat(missing);
            ui.label(RichText::new(&pad).text_style(mono.clone()));
        }

        ui.add_space(12.0);

        // ASCII preview with diff highlighting.
        for (i, &byte) in row.bytes.iter().enumerate() {
            let file_offset = row.offset + i as u64;
            let ch = ascii_char(byte);
            let (color, bg) =
                diff_byte_style(file_offset, changes, focused_idx, merged_regions, side);

            let resp = if let Some(bg_color) = bg {
                ui.add(
                    egui::Label::new(
                        RichText::new(ch.to_string())
                            .text_style(mono.clone())
                            .color(color)
                            .background_color(bg_color),
                    )
                    .sense(egui::Sense::click()),
                )
            } else {
                ui.label(
                    RichText::new(ch.to_string())
                        .text_style(mono.clone())
                        .color(color),
                )
            };

            if resp.clicked() {
                *clicked_offset = Some(file_offset);
            }
        }
    });
}

/// Determine the color/bg for a byte at the given offset.
fn diff_byte_style(
    offset: u64,
    changes: &[ChangedRange],
    focused_idx: Option<usize>,
    merged_regions: &[MergedRegion],
    side: DiffSide,
) -> (Color32, Option<Color32>) {
    let idx = changes.binary_search_by(|change| {
        let range = match side {
            DiffSide::Left => &change.left,
            DiffSide::Right => &change.right,
        };
        if offset < range.offset() {
            std::cmp::Ordering::Greater
        } else if offset >= range.end() {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    });

    if let Ok(i) = idx {
        if focused_idx == Some(i) {
            return (FOCUS_FG, Some(FOCUS_BG));
        }
        return (DIFF_FG, Some(DIFF_BG));
    }

    for mr in merged_regions {
        let range = match side {
            DiffSide::Left => &mr.left,
            DiffSide::Right => &mr.right,
        };
        if offset >= range.offset() && offset < range.end() {
            return (MERGED_FG, Some(MERGED_BG));
        }
    }

    (Color32::from_rgb(200, 200, 200), None)
}

/// Render the diff summary with change list, navigation, and merge controls.
fn render_diff_summary(ui: &mut Ui, diff: &mut DiffSession, status_message: &mut Option<String>) {
    ui.heading("Diff Summary");
    ui.separator();

    // Stats.
    egui::Grid::new("diff_stats_grid")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.strong("Left size:");
            ui.label(format!("{} bytes", diff.result.left_len));
            ui.end_row();

            ui.strong("Right size:");
            ui.label(format!("{} bytes", diff.result.right_len));
            ui.end_row();

            ui.strong("Changes:");
            ui.label(format!("{}", diff.result.change_count()));
            ui.end_row();

            ui.strong("Left changed:");
            ui.label(format!("{} bytes", diff.result.left_changed_bytes()));
            ui.end_row();

            ui.strong("Right changed:");
            ui.label(format!("{} bytes", diff.result.right_changed_bytes()));
            ui.end_row();

            if diff.result.is_identical() {
                ui.strong("Result:");
                ui.label("Files are identical");
                ui.end_row();
            }

            let left_patches = diff.left.patches.patch_count();
            let right_patches = diff.right.patches.patch_count();
            if left_patches > 0 || right_patches > 0 {
                ui.strong("Patches:");
                ui.label(format!("L: {left_patches}, R: {right_patches}"));
                ui.end_row();
            }
        });

    ui.add_space(8.0);
    ui.checkbox(&mut diff.sync_scroll, "Synchronized scroll");
    ui.add_space(8.0);

    // Undo / Redo / Revert controls per side.
    {
        let left_can_undo = diff.left.patches.can_undo();
        let left_can_redo = diff.left.patches.can_redo();
        let left_dirty = diff.left.patches.is_dirty();
        let right_can_undo = diff.right.patches.can_undo();
        let right_can_redo = diff.right.patches.can_redo();
        let right_dirty = diff.right.patches.is_dirty();

        let any_controls = left_can_undo
            || left_can_redo
            || left_dirty
            || right_can_undo
            || right_can_redo
            || right_dirty;

        if any_controls {
            let mut undo_action: Option<crate::state::DiffSide> = None;
            let mut redo_action: Option<crate::state::DiffSide> = None;
            let mut revert_action: Option<crate::state::DiffSide> = None;

            if left_can_undo || left_can_redo || left_dirty {
                ui.horizontal(|ui| {
                    ui.label("Left:");
                    if ui
                        .add_enabled(left_can_undo, egui::Button::new("Undo").small())
                        .clicked()
                    {
                        undo_action = Some(crate::state::DiffSide::Left);
                    }
                    if ui
                        .add_enabled(left_can_redo, egui::Button::new("Redo").small())
                        .clicked()
                    {
                        redo_action = Some(crate::state::DiffSide::Left);
                    }
                    if ui
                        .add_enabled(left_dirty, egui::Button::new("Revert").small())
                        .clicked()
                    {
                        revert_action = Some(crate::state::DiffSide::Left);
                    }
                });
            }
            if right_can_undo || right_can_redo || right_dirty {
                ui.horizontal(|ui| {
                    ui.label("Right:");
                    if ui
                        .add_enabled(right_can_undo, egui::Button::new("Undo").small())
                        .clicked()
                    {
                        undo_action = Some(crate::state::DiffSide::Right);
                    }
                    if ui
                        .add_enabled(right_can_redo, egui::Button::new("Redo").small())
                        .clicked()
                    {
                        redo_action = Some(crate::state::DiffSide::Right);
                    }
                    if ui
                        .add_enabled(right_dirty, egui::Button::new("Revert").small())
                        .clicked()
                    {
                        revert_action = Some(crate::state::DiffSide::Right);
                    }
                });
            }

            if let Some(side) = undo_action {
                diff.undo_side(side);
            }
            if let Some(side) = redo_action {
                diff.redo_side(side);
            }
            if let Some(side) = revert_action {
                diff.revert_side(side);
            }

            ui.add_space(4.0);
        }
    }

    // Navigation buttons.
    ui.horizontal(|ui| {
        let has_changes = diff.result.change_count() > 0;

        if ui
            .add_enabled(has_changes, egui::Button::new("|<"))
            .on_hover_text("First change")
            .clicked()
        {
            if let Some(idx) = diff.navigator.first() {
                scroll_to_change(diff, idx);
            }
        }
        if ui
            .add_enabled(has_changes, egui::Button::new("<"))
            .on_hover_text("Previous change")
            .clicked()
        {
            if let Some(idx) = diff.navigator.prev_change() {
                scroll_to_change(diff, idx);
            }
        }

        if let Some(idx) = diff.navigator.current_index() {
            ui.label(format!("{} / {}", idx + 1, diff.navigator.count()));
        } else if has_changes {
            ui.label(format!("- / {}", diff.navigator.count()));
        }

        if ui
            .add_enabled(has_changes, egui::Button::new(">"))
            .on_hover_text("Next change")
            .clicked()
        {
            if let Some(idx) = diff.navigator.next_change() {
                scroll_to_change(diff, idx);
            }
        }
        if ui
            .add_enabled(has_changes, egui::Button::new(">|"))
            .on_hover_text("Last change")
            .clicked()
        {
            if let Some(idx) = diff.navigator.last() {
                scroll_to_change(diff, idx);
            }
        }
    });

    // Bulk merge buttons.
    let mergeable_count = (0..diff.result.change_count())
        .filter(|&i| diff.can_merge(i))
        .count();
    if mergeable_count > 0 {
        ui.add_space(4.0);
        let mut bulk_action: Option<MergeDirection> = None;
        ui.horizontal(|ui| {
            if ui
                .button("Use All Left")
                .on_hover_text("Apply all left bytes to right")
                .clicked()
            {
                bulk_action = Some(MergeDirection::ToRight);
            }
            if ui
                .button("Use All Right")
                .on_hover_text("Apply all right bytes to left")
                .clicked()
            {
                bulk_action = Some(MergeDirection::ToLeft);
            }
        });
        if let Some(dir) = bulk_action {
            let indices: Vec<usize> = (0..diff.result.change_count())
                .rev()
                .filter(|&i| diff.can_merge(i))
                .collect();
            for i in indices {
                let result = match dir {
                    MergeDirection::ToRight => diff.merge_to_right(i),
                    MergeDirection::ToLeft => diff.merge_to_left(i),
                };
                if let Err(e) = result {
                    *status_message = Some(format!("Merge error: {e}"));
                    return;
                }
            }
            *status_message = Some(format!("Merged {mergeable_count} changes"));
            return;
        }
    }

    ui.separator();

    // Change list with per-change merge buttons.
    if diff.result.changes.is_empty() {
        ui.label("No differences found.");
    } else {
        let focused = diff.navigator.current_index();
        let change_count = diff.result.changes.len();
        let change_info: Vec<(String, bool)> = (0..change_count)
            .map(|i| {
                let label = format_change_label(i, &diff.result.changes[i]);
                let mergeable = diff.can_merge(i);
                (label, mergeable)
            })
            .collect();

        let mut clicked_index: Option<usize> = None;
        let mut merge_action: Option<(usize, MergeDirection)> = None;

        egui::ScrollArea::vertical()
            .id_salt("diff_change_list")
            .show(ui, |ui| {
                for (i, (label, mergeable)) in change_info.iter().enumerate() {
                    let is_focused = focused == Some(i);

                    ui.horizontal(|ui| {
                        let to_right_resp = ui
                            .add_enabled(*mergeable, egui::Button::new("L>R").small())
                            .on_hover_text("Use left bytes on right");
                        if to_right_resp.clicked() {
                            merge_action = Some((i, MergeDirection::ToRight));
                        }

                        let to_left_resp = ui
                            .add_enabled(*mergeable, egui::Button::new("R>L").small())
                            .on_hover_text("Use right bytes on left");
                        if to_left_resp.clicked() {
                            merge_action = Some((i, MergeDirection::ToLeft));
                        }

                        let resp = ui.selectable_label(is_focused, label);
                        if resp.clicked() {
                            clicked_index = Some(i);
                        }
                    });
                }
            });

        if let Some(i) = clicked_index {
            diff.navigator.go_to(i);
            scroll_to_change(diff, i);
        }

        if let Some((i, dir)) = merge_action {
            let result = match dir {
                MergeDirection::ToRight => diff.merge_to_right(i),
                MergeDirection::ToLeft => diff.merge_to_left(i),
            };
            match result {
                Ok(()) => {
                    *status_message = Some(format!("Merged change #{}", i + 1));
                }
                Err(e) => {
                    *status_message = Some(format!("Merge error: {e}"));
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum MergeDirection {
    ToRight,
    ToLeft,
}

fn format_change_label(index: usize, change: &ChangedRange) -> String {
    let left_start = change.left.offset();
    let right_start = change.right.offset();
    let left_len = change.left.length();
    let right_len = change.right.length();

    if left_len == right_len {
        format!("#{}: 0x{:X} ({} bytes)", index + 1, left_start, left_len,)
    } else {
        format!(
            "#{}: L 0x{:X} ({} B) / R 0x{:X} ({} B)",
            index + 1,
            left_start,
            left_len,
            right_start,
            right_len,
        )
    }
}

fn scroll_to_change(diff: &mut DiffSession, index: usize) {
    if let Some(change) = diff.result.changes.get(index) {
        let left_offset = change.left.offset();
        let right_offset = change.right.offset();

        let bpr = diff.left.hex.bytes_per_row() as u64;
        let left_row = left_offset / bpr;
        let right_row = right_offset / bpr;

        if diff.sync_scroll {
            let row = left_row.min(right_row);
            diff.left.hex.scroll_to_row(row);
            diff.right.hex.scroll_to_row(row);
        } else {
            diff.left.hex.scroll_to_row(left_row);
            diff.right.hex.scroll_to_row(right_row);
        }
    }
}
