use egui::{self, Color32, RichText, Ui};

use tinkerspark_core_bytes::ByteSource;
use tinkerspark_core_hexview::{
    self, ascii_char, build_rows, format_hex_byte, format_offset, offset_gutter_chars,
    parse_hex_pattern, visible_range, SearchDirection, SelectionMeta,
};
use tinkerspark_core_patch::PatchedView;
use tinkerspark_core_types::ByteRange;

use crate::state::{AppState, OpenFile, WorkspaceTab};

/// Render the workspace pane: tab bar + active tab content.
pub fn render_hex_pane(ui: &mut Ui, state: &mut AppState) {
    // Tab bar.
    render_tab_bar(ui, state);
    ui.separator();

    // Dispatch based on active tab.
    // Use direct field access to enable split borrows (tabs vs other fields).
    match state.tabs.get_mut(state.active_tab) {
        Some(WorkspaceTab::File { file, analysis }) => {
            let analysis_range = analysis.as_ref().and_then(|a| a.selected_range);
            render_file_hex_view(
                ui,
                file,
                analysis_range,
                &mut state.jump_to_input,
                &mut state.search_input,
                &mut state.search_hex_mode,
            );
        }
        Some(WorkspaceTab::Diff(diff)) => {
            crate::diff_pane::render_diff_tab(ui, diff, &mut state.status_message);
        }
        None => {
            render_empty(ui);
        }
    }
}

fn render_tab_bar(ui: &mut Ui, state: &mut AppState) {
    let mut switch_to: Option<usize> = None;
    let mut close_tab: Option<usize> = None;

    egui::ScrollArea::horizontal()
        .id_salt("workspace_tab_bar")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for (i, tab) in state.tabs.iter().enumerate() {
                    let is_active = i == state.active_tab;
                    let name = tab.name();
                    let label = if tab.is_dirty() {
                        format!("{name} *")
                    } else {
                        name
                    };

                    let resp = ui.selectable_label(is_active, &label);
                    if resp.clicked() {
                        switch_to = Some(i);
                    }

                    // Middle-click to close.
                    if resp.middle_clicked() {
                        close_tab = Some(i);
                    }

                    // Right-click context menu with close option.
                    resp.context_menu(|ui| {
                        if ui.button("Close").clicked() {
                            close_tab = Some(i);
                            ui.close_menu();
                        }
                    });
                }
            });
        });

    if let Some(i) = switch_to {
        state.active_tab = i;
    }
    if let Some(i) = close_tab {
        state.request_close_tab(i);
    }
}

fn render_file_hex_view(
    ui: &mut Ui,
    file: &mut OpenFile,
    analysis_range: Option<ByteRange>,
    jump_input: &mut String,
    search_input: &mut String,
    search_hex_mode: &mut bool,
) {
    let file_len = file.source.len();
    if file_len == 0 {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label("File is empty (0 bytes).");
        });
        return;
    }

    let patched = PatchedView::new(&*file.source, file.patches.patches());

    // Toolbar: jump-to-offset and search.
    render_toolbar(
        ui,
        &mut file.hex,
        &patched,
        jump_input,
        search_input,
        search_hex_mode,
    );

    ui.separator();

    // Compute layout metrics.
    let bpr = file.hex.bytes_per_row();
    let mono = egui::TextStyle::Monospace;
    let char_width = ui.fonts(|f| f.glyph_width(&ui.style().text_styles[&mono], '0'));
    let row_height = ui.text_style_height(&mono) + ui.spacing().item_spacing.y;

    let avail = ui.available_size();
    let visible_rows = ((avail.y / row_height) as usize).max(1);

    handle_keyboard(ui, &mut file.hex, visible_rows);

    let range = visible_range(file.hex.scroll_offset, visible_rows, bpr, file_len);

    let data = if range.length() > 0 {
        patched.read_range(range).unwrap_or_default()
    } else {
        Default::default()
    };

    let rows = build_rows(range.offset(), &data, bpr);

    let gutter_chars = offset_gutter_chars(file_len);
    let gutter_px = char_width * gutter_chars as f32 + 8.0;

    // Reserve a strip at the bottom for the selection status bar so it
    // doesn't get hidden behind the hex area's allocate_rect.
    let sel_bar_height = ui.text_style_height(&mono) + ui.spacing().item_spacing.y * 2.0 + 4.0;
    let full_area = ui.available_rect_before_wrap();
    let hex_area = egui::Rect::from_min_max(
        full_area.min,
        egui::pos2(full_area.max.x, full_area.max.y - sel_bar_height),
    );

    let hex_response = ui.allocate_rect(hex_area, egui::Sense::click_and_drag());

    let mut row_rects: Vec<egui::Rect> = Vec::with_capacity(rows.len());
    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(hex_area));
    for row in &rows {
        let rect = render_row(
            &mut child,
            row,
            bpr,
            file_len,
            &file.hex,
            analysis_range.as_ref(),
        );
        row_rects.push(rect);
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
        }
    }

    // --- Mouse drag selection ---
    let pointer_pos = ui.input(|i| i.pointer.interact_pos());

    if hex_response.clicked() || ui.input(|i| i.pointer.any_pressed()) {
        if let Some(pos) = pointer_pos {
            if hex_area.contains(pos) {
                if let Some(offset) =
                    hit_test_offset(pos, &row_rects, &rows, bpr, char_width, gutter_px)
                {
                    let shift = ui.input(|i| i.modifiers.shift);
                    if shift {
                        file.hex.select_to(offset);
                    } else {
                        file.hex.begin_drag(offset);
                    }
                }
            }
        }
    }

    if file.hex.drag_anchor.is_some() && ui.input(|i| i.pointer.is_decidedly_dragging()) {
        if let Some(pos) = pointer_pos {
            if let Some(offset) =
                hit_test_offset(pos, &row_rects, &rows, bpr, char_width, gutter_px)
            {
                file.hex.update_drag(offset);
            }
        }
    }

    if ui.input(|i| i.pointer.any_released()) {
        file.hex.end_drag();
    }

    if let Some(sel) = &file.hex.selection {
        let sel_range = ByteRange::new(sel.start(), sel.len());
        let patched_for_sel = PatchedView::new(&*file.source, file.patches.patches());
        if let Ok(sel_bytes) = patched_for_sel.read_range(sel_range) {
            let meta = SelectionMeta::from_bytes(sel, &sel_bytes);
            render_selection_status(ui, &meta);
        }
    }
}

fn render_empty(ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        ui.heading("Tinkerspark");
        ui.add_space(8.0);
        ui.label("No file open. Use File > Open to inspect a file.");
    });
}

fn render_toolbar(
    ui: &mut Ui,
    hex: &mut tinkerspark_core_hexview::HexViewState,
    source: &dyn ByteSource,
    jump_input: &mut String,
    search_input: &mut String,
    search_hex_mode: &mut bool,
) {
    ui.horizontal(|ui| {
        ui.label("Go to:");
        let jump_resp = ui.add(
            egui::TextEdit::singleline(jump_input)
                .desired_width(100.0)
                .hint_text("0x..."),
        );
        if jump_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            if let Some(offset) =
                tinkerspark_core_hexview::HexViewState::parse_jump_target(jump_input)
            {
                hex.jump_to(offset);
            }
        }

        ui.separator();

        ui.checkbox(search_hex_mode, "Hex");
        ui.label("Search:");
        let search_resp = ui.add(
            egui::TextEdit::singleline(search_input)
                .desired_width(160.0)
                .hint_text(if *search_hex_mode {
                    "FF 00 AB"
                } else {
                    "text..."
                }),
        );
        if search_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            do_search(
                hex,
                source,
                search_input,
                *search_hex_mode,
                SearchDirection::Forward,
            );
        }
        if ui.button("Next").clicked() {
            do_search(
                hex,
                source,
                search_input,
                *search_hex_mode,
                SearchDirection::Forward,
            );
        }
        if ui.button("Prev").clicked() {
            do_search(
                hex,
                source,
                search_input,
                *search_hex_mode,
                SearchDirection::Backward,
            );
        }
    });
}

fn do_search(
    hex: &mut tinkerspark_core_hexview::HexViewState,
    source: &dyn ByteSource,
    input: &str,
    hex_mode: bool,
    direction: SearchDirection,
) {
    let needle = if hex_mode {
        match parse_hex_pattern(input) {
            Some(b) if !b.is_empty() => b,
            _ => return,
        }
    } else {
        let bytes = input.as_bytes();
        if bytes.is_empty() {
            return;
        }
        bytes.to_vec()
    };

    let start = match direction {
        SearchDirection::Forward => hex.cursor.saturating_add(1),
        SearchDirection::Backward => hex.cursor.saturating_sub(1),
    };

    if let Some(hit) =
        tinkerspark_core_hexview::search::search_chunked(source, &needle, start, direction)
    {
        hex.jump_to(hit.offset);
        hex.select_to(hit.offset + hit.length as u64 - 1);
    }
}

fn render_row(
    ui: &mut Ui,
    row: &tinkerspark_core_hexview::HexRow,
    bytes_per_row: usize,
    file_len: u64,
    hex_state: &tinkerspark_core_hexview::HexViewState,
    analysis_range: Option<&ByteRange>,
) -> egui::Rect {
    let mono = egui::TextStyle::Monospace;

    let resp = ui.horizontal(|ui| {
        let offset_str = format_offset(row.offset, file_len);
        ui.label(
            RichText::new(&offset_str)
                .text_style(mono.clone())
                .color(Color32::GRAY),
        );

        ui.add_space(8.0);

        for (i, &byte) in row.bytes.iter().enumerate() {
            let file_offset = row.offset + i as u64;
            let hex = format_hex_byte(byte);
            let hex_str = std::str::from_utf8(&hex).unwrap_or("??");

            let is_cursor = file_offset == hex_state.cursor;
            let is_selected = hex_state
                .selection
                .as_ref()
                .is_some_and(|s| s.contains(file_offset));
            let is_analysis = analysis_range.is_some_and(|r| r.contains(file_offset));

            let color = if is_cursor {
                Color32::from_rgb(255, 200, 50)
            } else if is_selected {
                Color32::from_rgb(100, 150, 255)
            } else if is_analysis {
                Color32::from_rgb(120, 220, 180)
            } else {
                ui.visuals().text_color()
            };

            let bg = if is_cursor {
                Some(Color32::from_rgb(60, 60, 20))
            } else if is_selected {
                Some(Color32::from_rgb(30, 50, 80))
            } else if is_analysis {
                Some(Color32::from_rgb(20, 50, 40))
            } else {
                None
            };

            if let Some(bg_color) = bg {
                ui.label(
                    RichText::new(hex_str)
                        .text_style(mono.clone())
                        .color(color)
                        .background_color(bg_color),
                );
            } else {
                ui.label(RichText::new(hex_str).text_style(mono.clone()).color(color));
            }

            if i + 1 < row.bytes.len() && (i + 1) % 8 == 0 {
                ui.add_space(4.0);
            }
        }

        let missing = bytes_per_row.saturating_sub(row.bytes.len());
        if missing > 0 {
            let pad: String = "   ".repeat(missing);
            ui.label(RichText::new(&pad).text_style(mono.clone()));
        }

        ui.add_space(12.0);

        let ascii: String = row.bytes.iter().map(|&b| ascii_char(b)).collect();
        ui.label(
            RichText::new(&ascii)
                .text_style(mono.clone())
                .color(Color32::from_rgb(180, 180, 180)),
        );
    });
    resp.response.rect
}

fn hit_test_offset(
    pos: egui::Pos2,
    row_rects: &[egui::Rect],
    rows: &[tinkerspark_core_hexview::HexRow],
    bytes_per_row: usize,
    char_width: f32,
    gutter_px: f32,
) -> Option<u64> {
    if row_rects.is_empty() {
        return None;
    }

    let row_idx = row_rects.iter().rposition(|r| pos.y >= r.min.y)?;

    let last_bottom = row_rects.last().map(|r| r.max.y).unwrap_or(0.0);
    if pos.y > last_bottom + 10.0 {
        return None;
    }

    let row = rows.get(row_idx)?;
    let rect = row_rects[row_idx];

    let x_rel = pos.x - rect.min.x - gutter_px;
    if x_rel < 0.0 {
        return Some(row.offset);
    }

    let hex_cell_width = char_width * 3.0;
    let col = (x_rel / hex_cell_width) as usize;
    let byte_idx = col.min(bytes_per_row.saturating_sub(1));
    let byte_idx = byte_idx.min(row.bytes.len().saturating_sub(1));

    Some(row.offset + byte_idx as u64)
}

fn handle_keyboard(
    ui: &mut Ui,
    hex: &mut tinkerspark_core_hexview::HexViewState,
    visible_rows: usize,
) {
    let bpr = hex.bytes_per_row() as i64;
    let old_cursor = hex.cursor;

    ui.input(|i| {
        let shift = i.modifiers.shift;

        if i.key_pressed(egui::Key::ArrowRight) {
            hex.move_cursor(1, shift);
        }
        if i.key_pressed(egui::Key::ArrowLeft) {
            hex.move_cursor(-1, shift);
        }
        if i.key_pressed(egui::Key::ArrowDown) {
            hex.move_cursor(bpr, shift);
        }
        if i.key_pressed(egui::Key::ArrowUp) {
            hex.move_cursor(-bpr, shift);
        }
        if i.key_pressed(egui::Key::PageDown) {
            let delta = bpr * visible_rows.max(1) as i64;
            hex.move_cursor(delta, shift);
        }
        if i.key_pressed(egui::Key::PageUp) {
            let delta = -(bpr * visible_rows.max(1) as i64);
            hex.move_cursor(delta, shift);
        }
        if i.key_pressed(egui::Key::Home) {
            if i.modifiers.ctrl {
                hex.set_cursor(0);
            } else {
                let row_start = (hex.cursor / bpr as u64) * bpr as u64;
                hex.set_cursor(row_start);
            }
        }
        if i.key_pressed(egui::Key::End) {
            if i.modifiers.ctrl {
                hex.set_cursor(hex.file_len.saturating_sub(1));
            } else {
                let row_start = (hex.cursor / bpr as u64) * bpr as u64;
                let row_end = (row_start + bpr as u64 - 1).min(hex.file_len.saturating_sub(1));
                hex.set_cursor(row_end);
            }
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::A) {
            hex.select_all();
        }
    });

    if hex.cursor != old_cursor {
        hex.ensure_cursor_visible(visible_rows);
    }
}

fn render_selection_status(ui: &mut Ui, meta: &SelectionMeta) {
    ui.separator();
    ui.horizontal_wrapped(|ui| {
        let mono = egui::TextStyle::Monospace;
        ui.label(
            RichText::new(format!(
                "Sel: 0x{:X}..0x{:X} ({} bytes)",
                meta.start, meta.end_inclusive, meta.length
            ))
            .text_style(mono.clone()),
        );
        if let Some(v) = meta.u8_val {
            ui.label(RichText::new(format!("  u8:{v}")).text_style(mono.clone()));
        }
        if let Some(v) = meta.u16_le {
            ui.label(RichText::new(format!("  u16LE:{v}")).text_style(mono.clone()));
        }
        if let Some(v) = meta.u16_be {
            ui.label(RichText::new(format!("  u16BE:{v}")).text_style(mono.clone()));
        }
        if let Some(v) = meta.u32_le {
            ui.label(RichText::new(format!("  u32LE:{v}")).text_style(mono.clone()));
        }
    });
}
