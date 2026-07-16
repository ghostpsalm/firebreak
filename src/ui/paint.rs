//! Rendering for the main window, split out of ui.rs. Chrome bands use egui
//! painting with explicit fonts/colors from the design tokens; the rule
//! table is custom-painted for exact grid, checkbox-intent, chip, and
//! accent-edge fidelity.

use super::{cell_text, interactive_chip, App, DirFilter, Phase, Sort, Tab};
use crate::listeners::{self, Listener};
use crate::theme::{self as t};
use crate::time_util;
use eframe::egui::{self, Align2, Color32, Pos2, Rect, Sense, Stroke, Vec2};

const TITLEBAR_H: f32 = 32.0;

// ---- vector glyphs (Plex + egui fallback lack ▲ ▾ ✕ ✓ ⌕) ----
mod glyph {
    use eframe::egui::{self, Color32, Pos2, Rect, Stroke, Vec2};

    pub fn check(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        let s = size / 2.0;
        let a = Pos2::new(center.x - s, center.y - s * 0.1);
        let b = Pos2::new(center.x - s * 0.25, center.y + s * 0.6);
        let c = Pos2::new(center.x + s * 0.9, center.y - s * 0.7);
        let w = (size * 0.16).max(1.3);
        p.line_segment([a, b], Stroke::new(w, color));
        p.line_segment([b, c], Stroke::new(w, color));
    }

    pub fn cross(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        let s = size / 2.0;
        let w = (size * 0.14).max(1.2);
        p.line_segment([Pos2::new(center.x - s, center.y - s), Pos2::new(center.x + s, center.y + s)], Stroke::new(w, color));
        p.line_segment([Pos2::new(center.x + s, center.y - s), Pos2::new(center.x - s, center.y + s)], Stroke::new(w, color));
    }

    pub fn tri_down(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        let s = size / 2.0;
        p.add(egui::Shape::convex_polygon(
            vec![
                Pos2::new(center.x - s, center.y - s * 0.6),
                Pos2::new(center.x + s, center.y - s * 0.6),
                Pos2::new(center.x, center.y + s * 0.8),
            ],
            color,
            Stroke::NONE,
        ));
    }

    pub fn tri_up(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        let s = size / 2.0;
        p.add(egui::Shape::convex_polygon(
            vec![
                Pos2::new(center.x - s, center.y + s * 0.6),
                Pos2::new(center.x + s, center.y + s * 0.6),
                Pos2::new(center.x, center.y - s * 0.8),
            ],
            color,
            Stroke::NONE,
        ));
    }

    /// Advisory triangle with a hollow center dot — reads as a warning mark.
    pub fn warn_tri(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        tri_up(p, center, size, color);
    }

    /// Warning sign: filled triangle with a white exclamation mark.
    pub fn warn_sign(p: &egui::Painter, center: Pos2, size: f32, color: Color32) {
        let s = size / 2.0;
        p.add(egui::Shape::convex_polygon(
            vec![
                Pos2::new(center.x - s, center.y + s * 0.75),
                Pos2::new(center.x + s, center.y + s * 0.75),
                Pos2::new(center.x, center.y - s * 0.85),
            ],
            color,
            Stroke::NONE,
        ));
        // exclamation: stem + dot in white
        let top = center.y - s * 0.1;
        p.line_segment(
            [Pos2::new(center.x, top), Pos2::new(center.x, center.y + s * 0.25)],
            Stroke::new((size * 0.11).max(1.2), Color32::WHITE),
        );
        p.circle_filled(Pos2::new(center.x, center.y + s * 0.5), (size * 0.075).max(0.9), Color32::WHITE);
    }

    pub fn magnifier(p: &egui::Painter, center: Pos2, color: Color32) {
        let r = 4.0;
        let c = Pos2::new(center.x - 1.0, center.y - 1.0);
        p.circle_stroke(c, r, Stroke::new(1.3, color));
        p.line_segment(
            [Pos2::new(c.x + r * 0.7, c.y + r * 0.7), Pos2::new(c.x + r * 1.6, c.y + r * 1.6)],
            Stroke::new(1.3, color),
        );
    }

    pub fn minimize(p: &egui::Painter, center: Pos2, color: Color32) {
        p.line_segment([Pos2::new(center.x - 5.0, center.y), Pos2::new(center.x + 5.0, center.y)], Stroke::new(1.2, color));
    }

    /// Windowed → offer maximize: a single square.
    pub fn maximize(p: &egui::Painter, center: Pos2, color: Color32) {
        let r = Rect::from_center_size(center, Vec2::splat(9.0));
        p.rect_stroke(r, 0.0, Stroke::new(1.2, color));
    }

    /// Maximized → offer restore: two overlapping squares.
    pub fn restore(p: &egui::Painter, center: Pos2, color: Color32) {
        let s = 7.5;
        // back square (top-right)
        let back = Rect::from_min_size(Pos2::new(center.x - s / 2.0 + 2.0, center.y - s / 2.0 - 2.0), Vec2::splat(s));
        p.rect_stroke(back, 0.0, Stroke::new(1.1, color));
        // front square (bottom-left), painted over with the panel fill behind
        let front = Rect::from_min_size(Pos2::new(center.x - s / 2.0 - 2.0, center.y - s / 2.0 + 2.0), Vec2::splat(s));
        p.rect_filled(front, 0.0, crate::theme::TITLEBAR);
        p.rect_stroke(front, 0.0, Stroke::new(1.1, color));
    }
}

pub fn window(app: &mut App, ctx: &egui::Context) {
    titlebar(app, ctx);
    header(app, ctx);
    if let Some(hours) = app.young_evidence_hours() {
        if !app.warning_acked {
            warning_band(app, ctx, hours);
        }
    } else if !app.ctx_info.note.is_empty() {
        note_band(app, ctx);
    }
    if app.phase == Phase::NeedsEnable {
        firstrun_band(app, ctx);
    }
    filter_bar(app, ctx);
    footer(app, ctx);
    drawer(app, ctx);
    if app.selected.is_some() {
        detail_panel(app, ctx);
    }
    central(app, ctx);
    if app.confirm_open {
        confirm_modal(app, ctx);
    }
    about_box(app, ctx);
    // 1px window border on a foreground layer (we draw our own chrome)
    let screen = ctx.screen_rect();
    ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("winborder")))
        .rect_stroke(screen.shrink(0.5), 0.0, Stroke::new(1.0, t::BORDER));
}

// ---- title bar ----

fn titlebar(app: &mut App, ctx: &egui::Context) {
    let logo = app.logo_texture(ctx);
    egui::TopBottomPanel::top("titlebar")
        .exact_height(TITLEBAR_H)
        .frame(egui::Frame::none().fill(t::TITLEBAR))
        .show(ctx, |ui| {
            let rect = ui.max_rect();
            // window controls occupy the right ~138px; the rest is a drag zone
            let controls_w = 46.0 * 3.0;
            let drag_rect = Rect::from_min_max(rect.min, Pos2::new(rect.right() - controls_w, rect.bottom()));
            let drag = ui.interact(drag_rect, ui.id().with("tb_drag"), Sense::click_and_drag());
            if drag.drag_started() {
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
            if drag.double_clicked() {
                let maxed = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maxed));
            }

            let p = ui.painter();
            super::stroke_bottom(p, rect, t::BORDER);
            let logo_rect = Rect::from_min_size(Pos2::new(rect.left() + 10.0, rect.center().y - 9.0), Vec2::splat(18.0));
            p.image(logo.id(), logo_rect, Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)), Color32::WHITE);
            let name_pos = Pos2::new(logo_rect.right() + 8.0, rect.center().y);
            let name_galley = p.layout_no_wrap("firebreak".to_string(), t::semibold(12.0), t::INK);
            p.galley(Pos2::new(name_pos.x, name_pos.y - name_galley.size().y / 2.0), name_galley.clone(), t::INK);
            let host = if app.ctx_info.hostname.is_empty() { String::new() } else { format!(" · {}", app.ctx_info.hostname) };
            // catchline sits just after the name (small fixed gap), not floated far right
            p.text(Pos2::new(name_pos.x + name_galley.size().x + 12.0, rect.center().y), Align2::LEFT_CENTER, format!("— Windows Firewall Audit{host}"), t::sans(11.0), t::FAINT);

            // min / max / close — each a 46px hit target
            let maximized = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
            for i in 0..3u8 {
                let bx = Rect::from_min_size(Pos2::new(rect.right() - 46.0 * (3.0 - i as f32), rect.top()), Vec2::new(46.0, TITLEBAR_H));
                let r = ui.interact(bx, ui.id().with(("winbtn", i)), Sense::click());
                let hovered = r.hovered();
                if hovered {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                let is_close = i == 2;
                if hovered {
                    ui.painter().rect_filled(bx, 0.0, if is_close { t::DESTRUCTIVE } else { Color32::from_rgb(0xDD, 0xE1, 0xE6) });
                }
                let col = if hovered && is_close { Color32::WHITE } else { t::TERTIARY };
                let c = bx.center();
                match i {
                    0 => glyph::minimize(ui.painter(), c, col),
                    1 => {
                        if maximized {
                            glyph::restore(ui.painter(), c, col);
                        } else {
                            glyph::maximize(ui.painter(), c, col);
                        }
                    }
                    _ => glyph::cross(ui.painter(), c, 9.0, col),
                }
                if r.clicked() {
                    match i {
                        0 => ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true)),
                        1 => ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized)),
                        _ => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                    }
                }
            }
        });
}

// ---- evidence header ----

fn header(app: &mut App, ctx: &egui::Context) {
    egui::TopBottomPanel::top("header")
        .frame(egui::Frame::none().fill(Color32::WHITE).inner_margin(egui::Margin::symmetric(PAGE, 10.0)))
        .show(ctx, |ui| {
            super::stroke_bottom(ui.painter(), ui.max_rect().expand2(Vec2::new(PAGE, 10.0)), t::BORDER_LIGHT);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                // before the audit check completes, don't assert "off"
                if !app.audit_checked && app.phase == Phase::Loading {
                    dot(ui, t::ADVISORY);
                    ui.add_space(8.0);
                    stat(ui, "Detecting…", "checking Windows audit policy");
                    return;
                }
                let active = app.ctx_info.auditing_active;
                dot(ui, if active { t::LIVE } else { t::CB_EMPTY_BORDER });
                ui.add_space(8.0);
                if active {
                    let since = app
                        .ctx_info
                        .collection_started
                        .as_deref()
                        .map(time_util::since_with_age)
                        .unwrap_or_else(|| "just now".into());
                    stat(ui, "Auditing active", &format!("Since {since}"));
                    ui.add_space(8.0);
                    // Stop control — disables auditing (and returns to the
                    // first-run view, handy for testing that state too)
                    if flat_button(ui, "Stop").clicked() {
                        app.stop_auditing(ctx);
                    }
                } else {
                    stat(ui, "Auditing is off", "No connection data has ever been collected");
                }

                if active {
                    divider(ui);
                    let last = app
                        .ctx_info
                        .last_ingest
                        .as_deref()
                        .map(|s| format!("This run · Last Ingest {}", time_util::relative(s)))
                        .unwrap_or_else(|| "This run".into());
                    let events = if app.phase == Phase::Loading || app.phase == Phase::Enabling {
                        format!("Ingesting… {}", app.progress)
                    } else {
                        format!("{} events", t::fmt_thousands(app.ctx_info.events_processed as i64))
                    };
                    stat(ui, &events, &last);

                    divider(ui);
                    let gap = !app.ctx_info.note.is_empty();
                    let young = app.young_evidence_hours().is_some();
                    let value = if gap { "Coverage gap" } else { "Coverage complete" };
                    if young && app.warning_acked {
                        // warning persists but was dismissed — offer to reopen it
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.label(egui::RichText::new(value).font(t::semibold(12.0)).color(t::INK));
                            if link(ui, "See warning", t::ADVISORY_HEADER).clicked() {
                                app.warning_acked = false;
                            }
                        });
                    } else {
                        let caption = if gap || young {
                            "See warning below"
                        } else {
                            "No gaps detected in Audit Log"
                        };
                        stat(ui, value, caption);
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let settings = settings_button(ui);
                    let just_toggled = settings.clicked();
                    if just_toggled {
                        app.settings_open = !app.settings_open;
                    }
                    settings_menu(app, ui, ctx, settings.rect, just_toggled);
                    if active {
                        ui.add_space(8.0);
                        if flat_button(ui, "Refresh now").clicked() {
                            if let (Some(db), Phase::Ready) = (app.db_path.clone(), app.phase) {
                                app.phase = Phase::Loading;
                                app.spawn_detect(db, ctx.clone());
                            }
                        }
                    }
                });
            });
        });
}

fn dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(8.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
}

fn stat(ui: &mut egui::Ui, value: &str, caption: &str) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 1.0;
        ui.label(egui::RichText::new(value).font(t::semibold(12.0)).color(t::INK));
        ui.label(egui::RichText::new(caption).font(t::sans(11.0)).color(t::TERTIARY));
    });
}

fn divider(ui: &mut egui::Ui) {
    ui.add_space(24.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(1.0, 26.0), Sense::hover());
    ui.painter().vline(rect.center().x, rect.y_range(), Stroke::new(1.0, t::BORDER_LIGHT));
    ui.add_space(24.0);
}

const PAGE: f32 = super::PAGE_PAD;

fn flat_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(label.to_string(), t::sans(12.0), t::INK);
    let size = Vec2::new(galley.size().x + 24.0, galley.size().y + 10.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let (fill, border) = if resp.is_pointer_button_down_on() {
        (t::CHROME, t::ACCENT)
    } else if resp.hovered() {
        (Color32::WHITE, t::ACCENT)
    } else {
        (t::RAISED, t::CONTROL_BORDER)
    };
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    ui.painter().rect(rect, 0.0, fill, Stroke::new(1.0, border));
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, t::INK);
    resp
}

/// A text link that shows the hand cursor and underlines/darkens on hover.
fn link(ui: &mut egui::Ui, label: &str, color: Color32) -> egui::Response {
    let resp = ui.add(
        egui::Label::new(egui::RichText::new(label).font(t::sans(12.0)).color(color).underline())
            .sense(Sense::click()),
    );
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}

/// Dropdown anchored under the Settings button.
fn settings_menu(app: &mut App, _ui: &mut egui::Ui, ctx: &egui::Context, anchor: Rect, just_toggled: bool) {
    if !app.settings_open {
        return;
    }
    let area = egui::Area::new(egui::Id::new("settings_menu"))
        .order(egui::Order::Foreground)
        .fixed_pos(Pos2::new(anchor.right() - 210.0, anchor.bottom() + 2.0));
    let resp = area.show(ctx, |ui| {
        egui::Frame::none()
            .fill(Color32::WHITE)
            .stroke(Stroke::new(1.0, t::CONTROL_BORDER))
            .inner_margin(egui::Margin::same(4.0))
            .show(ui, |ui| {
                ui.set_width(202.0);
                let ready = app.phase == Phase::Ready && app.db_path.is_some();
                if menu_item(ui, "Export usage to CSV…", app.phase == Phase::Ready && !app.rows.is_empty()) {
                    do_export_csv(app);
                    app.settings_open = false;
                }
                if menu_item(ui, "Import events from .evtx…", app.db_path.is_some()) {
                    app.settings_open = false;
                    do_import_evtx(app, ctx);
                }
                if menu_item(ui, "Rescan entire log", ready) {
                    if let Some(db) = app.db_path.clone() {
                        let _ = crate::pipeline::reset(&db);
                        app.phase = Phase::Loading;
                        app.spawn_detect(db, ctx.clone());
                    }
                    app.settings_open = false;
                }
                if menu_item(ui, "Restore audit policy", app.db_path.is_some()) {
                    if let Some(db) = app.db_path.clone() {
                        if let Ok(store) = crate::store::Store::open(&db) {
                            app.status = match crate::pipeline::restore_audit_state(&store) {
                                Ok(m) => m,
                                Err(e) => format!("Restore failed: {e:#}"),
                            };
                        }
                    }
                    app.settings_open = false;
                }
                if menu_item(ui, "Open data folder", true) {
                    open_data_folder();
                    app.settings_open = false;
                }
                ui.separator();
                if menu_item(ui, "Check for updates…", true) {
                    app.status = format!(
                        "firebreak {} — no update channel configured; check your source for newer builds.",
                        env!("CARGO_PKG_VERSION")
                    );
                    app.settings_open = false;
                }
                if menu_item(ui, "About firebreak", true) {
                    app.about_open = true;
                    app.settings_open = false;
                }
            });
    });
    // click-away closes — but not on the very frame the Settings button was
    // clicked to open it (that click reads as "elsewhere" to the menu area)
    if !just_toggled && resp.response.clicked_elsewhere() {
        app.settings_open = false;
    }
}

fn open_data_folder() {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    let dir = std::path::Path::new(&base).join("firebreak");
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(windows)]
    {
        let explorer = std::path::Path::new(
            &std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()),
        )
        .join("explorer.exe");
        let _ = crate::syspath::command(explorer).arg(&dir).spawn();
    }
}

#[cfg(windows)]
fn do_export_csv(app: &mut App) {
    let default = crate::pipeline::default_csv_name();
    if let Some(path) = rfd::FileDialog::new()
        .add_filter("CSV", &["csv"])
        .set_file_name(&default)
        .set_title("Export rule usage to CSV")
        .save_file()
    {
        app.status = match crate::pipeline::export_csv(&app.rows, &path) {
            Ok(()) => format!("Exported {} rules → {}", app.rows.len(), path.display()),
            Err(e) => format!("CSV export failed: {e:#}"),
        };
    }
}

#[cfg(not(windows))]
fn do_export_csv(app: &mut App) {
    // preview/dev: no dialog — write next to the working dir
    let path = std::path::PathBuf::from(crate::pipeline::default_csv_name());
    app.status = match crate::pipeline::export_csv(&app.rows, &path) {
        Ok(()) => format!("Exported {} rules → {}", app.rows.len(), path.display()),
        Err(e) => format!("CSV export failed: {e:#}"),
    };
}

#[cfg(windows)]
fn do_import_evtx(app: &mut App, ctx: &egui::Context) {
    let Some(path) = rfd::FileDialog::new()
        .add_filter("Windows event log", &["evtx"])
        .set_title("Import a saved Security .evtx")
        .pick_file()
    else {
        return;
    };
    // if an import session is already open, ask whether to add or start fresh
    let append = if app.import_db.is_some() {
        match rfd::MessageDialog::new()
            .set_title("Import events")
            .set_description(
                "Add these events to the current import (for reviewing multiple machines \
                 together)?\n\nYes = add · No = start a new import from just this file.",
            )
            .set_buttons(rfd::MessageButtons::YesNo)
            .show()
        {
            rfd::MessageDialogResult::Yes => true,
            _ => false,
        }
    } else {
        false
    };
    app.spawn_import(path, append, ctx.clone());
}

#[cfg(not(windows))]
fn do_import_evtx(app: &mut App, _ctx: &egui::Context) {
    app.status = "Import is only available on Windows.".into();
}

fn menu_item(ui: &mut egui::Ui, label: &str, enabled: bool) -> bool {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 24.0), if enabled { Sense::click() } else { Sense::hover() });
    if enabled && resp.hovered() {
        ui.painter().rect_filled(rect, 0.0, t::ACCENT_TINT);
    }
    let col = if enabled { t::INK } else { t::DISABLED };
    ui.painter().text(Pos2::new(rect.left() + 8.0, rect.center().y), Align2::LEFT_CENTER, label, t::sans(12.0), col);
    enabled && resp.clicked()
}

fn about_box(app: &mut App, ctx: &egui::Context) {
    if !app.about_open {
        return;
    }
    egui::Area::new(egui::Id::new("about_scrim")).order(egui::Order::Background).show(ctx, |ui| {
        ui.painter().rect_filled(ctx.screen_rect(), 0.0, Color32::from_rgba_unmultiplied(44, 62, 80, 90));
    });
    let mut open = true;
    egui::Window::new("about")
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .fixed_size(Vec2::new(360.0, 0.0))
        .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
        .frame(egui::Frame::none().fill(Color32::WHITE).stroke(Stroke::new(1.0, t::CONTROL_BORDER)))
        .show(ctx, |ui| {
            ui.add_space(18.0);
            let logo = app.logo_texture(ctx);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                let (r, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
                ui.painter().image(logo.id(), r, Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)), Color32::WHITE);
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("firebreak").font(t::semibold(15.0)).color(t::INK));
                    ui.label(egui::RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION"))).font(t::mono(11.0)).color(t::SECONDARY));
                });
            });
            ui.add_space(12.0);
            for line in [
                "Windows Firewall rule-usage auditor.",
                "Correlates WFP connection audit events (5156/5157)",
                "with firewall rules to find unused and over-broad rules.",
            ] {
                ui.horizontal(|ui| {
                    ui.add_space(20.0);
                    ui.label(egui::RichText::new(line).font(t::sans(11.5)).color(t::SECONDARY));
                });
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add_space(20.0);
                ui.label(egui::RichText::new(format!("Host: {}", app.ctx_info.hostname)).font(t::mono(11.0)).color(t::TERTIARY));
            });
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(20.0);
                    if primary_button(ui, "Close", t::ACCENT).clicked() {
                        open = false;
                    }
                });
            });
            ui.add_space(16.0);
        });
    if !open {
        app.about_open = false;
    }
}

/// "Settings ▾" with a drawn caret.
fn settings_button(ui: &mut egui::Ui) -> egui::Response {
    let galley = ui.painter().layout_no_wrap("Settings".to_string(), t::sans(12.0), t::INK);
    let size = Vec2::new(galley.size().x + 34.0, galley.size().y + 10.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let (fill, border) = if resp.hovered() { (Color32::WHITE, t::ACCENT) } else { (t::RAISED, t::CONTROL_BORDER) };
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    ui.painter().rect(rect, 0.0, fill, Stroke::new(1.0, border));
    ui.painter().galley(Pos2::new(rect.left() + 12.0, rect.center().y - galley.size().y / 2.0), galley, t::INK);
    glyph::tri_down(ui.painter(), Pos2::new(rect.right() - 12.0, rect.center().y), 8.0, t::TERTIARY);
    resp
}

// ---- warning band ----

fn warning_band(app: &mut App, ctx: &egui::Context, hours: f64) {
    egui::TopBottomPanel::top("warning")
        .frame(egui::Frame::none().fill(t::ADVISORY_BG).inner_margin(egui::Margin::symmetric(PAGE, 8.0)))
        .show(ctx, |ui| {
            super::stroke_bottom(ui.painter(), ui.max_rect().expand2(Vec2::new(PAGE, 8.0)), t::ADVISORY_BORDER);
            ui.horizontal(|ui| {
                // drawn warning triangle with an exclamation, not a text glyph
                let (r, _) = ui.allocate_exact_size(Vec2::new(15.0, 15.0), Sense::hover());
                glyph::warn_sign(ui.painter(), r.center(), 13.0, t::ADVISORY);
                ui.add_space(6.0);
                let human = if hours < 48.0 {
                    format!("Only {} hours of evidence.", hours.round() as i64)
                } else {
                    format!("Only {} days of evidence.", (hours / 24.0).round() as i64)
                };
                let mut job = egui::text::LayoutJob::default();
                job.append(&human, 0.0, fmt(t::semibold(12.0), t::ADVISORY_TEXT));
                job.append(
                    "  Zero-hit values are not yet meaningful — weekly and monthly traffic hasn't \
                     had a chance to occur.",
                    0.0,
                    fmt(t::sans(12.0), t::ADVISORY_TEXT),
                );
                ui.label(job);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if link(ui, "Acknowledge", t::ADVISORY_HEADER).clicked() {
                        app.warning_acked = true;
                    }
                });
            });
        });
}

fn note_band(app: &App, ctx: &egui::Context) {
    egui::TopBottomPanel::top("note")
        .frame(egui::Frame::none().fill(t::ADVISORY_BG).inner_margin(egui::Margin::symmetric(PAGE, 8.0)))
        .show(ctx, |ui| {
            super::stroke_bottom(ui.painter(), ui.max_rect().expand2(Vec2::new(PAGE, 8.0)), t::ADVISORY_BORDER);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("▲").font(t::sans(12.0)).color(t::ADVISORY));
                ui.add_space(6.0);
                ui.label(egui::RichText::new(&app.ctx_info.note).font(t::sans(12.0)).color(t::ADVISORY_TEXT));
            });
        });
}

fn fmt(font: egui::FontId, color: Color32) -> egui::text::TextFormat {
    egui::text::TextFormat { font_id: font, color, ..Default::default() }
}

// ---- first-run band ----

fn firstrun_band(app: &mut App, ctx: &egui::Context) {
    egui::TopBottomPanel::top("firstrun")
        .frame(egui::Frame::none().fill(t::ACCENT_TINT).inner_margin(egui::Margin::symmetric(PAGE, 12.0)))
        .show(ctx, |ui| {
            super::stroke_bottom(ui.painter(), ui.max_rect().expand2(Vec2::new(PAGE, 12.0)), t::ACCENT_TINT_BORDER);
            ui.horizontal(|ui| {
                let enabling = app.phase == Phase::Enabling;
                let label = if enabling { "Enabling…" } else { "Enable connection auditing" };
                let galley = ui.painter().layout_no_wrap(label.to_string(), t::semibold(13.0), Color32::WHITE);
                let size = Vec2::new(galley.size().x + 40.0, galley.size().y + 16.0);
                let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
                let fill = if enabling { t::ACCENT.gamma_multiply(0.6) } else if resp.hovered() { t::ACCENT.gamma_multiply(1.1) } else { t::ACCENT };
                ui.painter().rect_filled(rect, 0.0, fill);
                ui.painter().galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
                if resp.clicked() && !enabling {
                    app.start_enable(ctx);
                }
                ui.add_space(16.0);
                let mut job = egui::text::LayoutJob::default();
                job.wrap.max_width = ui.available_width();
                job.append(
                    "Turns on Windows Filtering Platform audit events (security log, ~40 MB/day at typical load). ",
                    0.0, fmt(t::sans(12.0), t::INK));
                job.append("Nothing is blocked or modified", 0.0, fmt(t::semibold(12.0), t::INK));
                job.append(
                    " — firebreak only records which rules the traffic matches. Usage columns fill in as evidence \
                     accumulates; plan on ~7–14 days before zero-hit values mean anything.",
                    0.0, fmt(t::sans(12.0), t::INK));
                ui.label(job);
            });
        });
}

// ---- filter bar ----

const CTRL_H: f32 = 25.0; // shared height for all filter-bar controls

fn filter_bar(app: &mut App, ctx: &egui::Context) {
    egui::TopBottomPanel::top("filterbar")
        .frame(egui::Frame::none().fill(t::CHROME).inner_margin(egui::Margin::symmetric(PAGE, 7.0)))
        .show(ctx, |ui| {
            super::stroke_bottom(ui.painter(), ui.max_rect().expand2(Vec2::new(PAGE, 7.0)), t::BORDER_LIGHT);
            // one row, everything vertically centered to CTRL_H so the groups
            // line up exactly
            ui.horizontal(|ui| {
                ui.set_height(CTRL_H);
                ui.spacing_mut().item_spacing = Vec2::new(6.0, 0.0);

                // search box — reserve the field rect first, draw the
                // magnifier at a FIXED left inset, then place the TextEdit
                // with its text indented past the icon (no overlap, icon
                // doesn't move with the text)
                let (field, _) = ui.allocate_exact_size(Vec2::new(224.0, CTRL_H), Sense::hover());
                ui.painter().rect(field, 0.0, Color32::WHITE, Stroke::new(1.0, t::CONTROL_BORDER));
                glyph::magnifier(ui.painter(), Pos2::new(field.left() + 12.0, field.center().y), t::FAINT);
                let text_area = Rect::from_min_max(
                    Pos2::new(field.left() + 24.0, field.top()),
                    Pos2::new(field.right() - 6.0, field.bottom()),
                );
                let mut child = ui.child_ui(text_area, egui::Layout::left_to_right(egui::Align::Center), None);
                child.add(
                    egui::TextEdit::singleline(&mut app.filter_text)
                        .hint_text("Filter rules…")
                        .desired_width(f32::INFINITY)
                        .font(t::sans(12.0))
                        .frame(false),
                );

                // direction filter (default In) — the primary audit lens
                let dir = app.dir_filter;
                let mut new_dir = dir;
                segmented_choice(ui, &[
                    ("In", DirFilter::In),
                    ("Out", DirFilter::Out),
                    ("All", DirFilter::All),
                ], dir, &mut new_dir);
                app.dir_filter = new_dir;

                ui.add_space(4.0);
                let zero_enabled = app.ctx_info.auditing_active;
                segmented_toggles(ui, &mut [
                    ("Enabled only", &mut app.only_enabled, true),
                    ("Zero-hit", &mut app.only_zero_hit, zero_enabled),
                    ("Flagged", &mut app.only_flagged, true),
                ]);
                ui.add_space(4.0);
                segmented_toggles(ui, &mut [
                    ("Domain", &mut app.show_domain, true),
                    ("Private", &mut app.show_private, true),
                    ("Public", &mut app.show_public, true),
                ]);

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let total = app.rows.len();
                    let shown = app.visible().len();
                    let mut job = egui::text::LayoutJob::default();
                    job.append(&t::fmt_thousands(total as i64), 0.0, fmt(t::semibold(11.5), t::INK));
                    job.append(" rules · ", 0.0, fmt(t::sans(11.5), t::TERTIARY));
                    job.append(&t::fmt_thousands(shown as i64), 0.0, fmt(t::semibold(11.5), t::INK));
                    job.append(" shown", 0.0, fmt(t::sans(11.5), t::TERTIARY));
                    ui.label(job);
                });
            });
        });
}

/// One segment cell of a segmented control; returns its click response.
/// `first` controls the left border; height is fixed to CTRL_H so groups
/// align regardless of label width.
fn segment_cell(ui: &mut egui::Ui, label: &str, active: bool, enabled: bool, first: bool) -> egui::Response {
    let text_col = if active { Color32::WHITE } else if enabled { t::SECONDARY } else { t::CB_EMPTY_BORDER };
    let galley = ui.painter().layout_no_wrap(label.to_string(), t::sans(11.5), text_col);
    let w = galley.size().x + 20.0;
    let sense = if enabled { Sense::click() } else { Sense::hover() };
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, CTRL_H), sense);
    let fill = if active { t::DARK_SEGMENT } else if resp.hovered() && enabled { t::HOVER_WASH } else { Color32::WHITE };
    ui.painter().rect_filled(rect, 0.0, fill);
    let border = Stroke::new(1.0, t::CONTROL_BORDER);
    ui.painter().hline(rect.x_range(), rect.top() + 0.5, border);
    ui.painter().hline(rect.x_range(), rect.bottom() - 0.5, border);
    ui.painter().vline(rect.right() - 0.5, rect.y_range(), border);
    if first {
        ui.painter().vline(rect.left() + 0.5, rect.y_range(), border);
    }
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, text_col);
    resp
}

/// Segmented multi-toggle (each cell independently on/off).
fn segmented_toggles(ui: &mut egui::Ui, segs: &mut [(&str, &mut bool, bool)]) {
    let prev = ui.spacing().item_spacing;
    ui.spacing_mut().item_spacing.x = 0.0;
    for (i, (label, state, enabled)) in segs.iter_mut().enumerate() {
        if segment_cell(ui, label, **state, *enabled, i == 0).clicked() && *enabled {
            **state = !**state;
        }
    }
    ui.spacing_mut().item_spacing = prev;
}

/// Segmented single-choice (exactly one active).
fn segmented_choice<T: PartialEq + Copy>(ui: &mut egui::Ui, segs: &[(&str, T)], current: T, out: &mut T) {
    let prev = ui.spacing().item_spacing;
    ui.spacing_mut().item_spacing.x = 0.0;
    for (i, (label, val)) in segs.iter().enumerate() {
        if segment_cell(ui, label, *val == current, true, i == 0).clicked() {
            *out = *val;
        }
    }
    ui.spacing_mut().item_spacing = prev;
}

// ---- central: table + empty state ----

struct Cols {
    check: f32,
    name: (f32, f32),
    dir: (f32, f32),
    action: (f32, f32),
    profiles: (f32, f32),
    scope: (f32, f32),
    hits: (f32, f32),
    last: (f32, f32),
    apps: (f32, f32),
    listen: (f32, f32),
}

impl Cols {
    fn compute(left: f32, width: f32, cw: &super::ColWidths) -> Cols {
        let fixed = 34.0 + cw.dir + cw.action + cw.profiles + cw.scope + cw.hits + cw.last + cw.listen;
        let flex = (width - fixed).max(300.0);
        let name_w = (flex * (1.35 / 2.35)).max(190.0);
        let apps_w = (flex - name_w).max(100.0);
        let mut x = left;
        let mut col = |w: f32| {
            let a = x;
            x += w;
            (a, w)
        };
        Cols {
            check: col(34.0).0,
            name: col(name_w),
            dir: col(cw.dir),
            action: col(cw.action),
            profiles: col(cw.profiles),
            scope: col(cw.scope),
            hits: col(cw.hits),
            last: col(cw.last),
            apps: col(apps_w),
            listen: col(cw.listen),
        }
    }
}

/// Text indent inside a column cell so content isn't flush against the
/// separator on its left.
const CELL_PAD: f32 = 8.0;

fn central(app: &mut App, ctx: &egui::Context) {
    egui::CentralPanel::default()
        .frame(egui::Frame::none().fill(Color32::WHITE))
        .show(ctx, |ui| {
            if app.rows.is_empty() && matches!(app.phase, Phase::Loading | Phase::Enabling) {
                ui.centered_and_justified(|ui| {
                    ui.label(egui::RichText::new(&app.progress).font(t::sans(12.0)).color(t::SECONDARY));
                });
                return;
            }
            let full = ui.max_rect();
            let cw = app.col_w;
            let cols = Cols::compute(full.left(), full.width(), &cw);
            let visible = app.visible();
            if visible.is_empty() {
                table_header(ui, app, &cols);
                empty_state(app, ui);
                return;
            }
            // rows first, in the area below the header…
            let row_area = Rect::from_min_max(
                Pos2::new(full.left(), full.top() + HEADER_H),
                full.max,
            );
            let mut child = ui.child_ui(row_area, egui::Layout::top_down(egui::Align::Min), None);
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show_rows(
                &mut child,
                ROW_H,
                visible.len(),
                |ui, range| {
                    for vi in range {
                        let ri = visible[vi];
                        let (rect, resp) = ui.allocate_exact_size(Vec2::new(cols.listen.0 + cols.listen.1 - full.left(), ROW_H), Sense::click());
                        let rc = Cols::compute(rect.left(), rect.width(), &cw);
                        row(app, ui, ri, rect, &rc, resp);
                    }
                },
            );
            // …then the header on top, so its bottom rule is always visible
            // even when rows scroll up under it
            table_header(ui, app, &cols);
        });
}

/// Column boundaries that carry a draggable resize handle, paired with a
/// mutable-width selector into ColWidths. The right edge of each fixed
/// column is a handle that grows/shrinks that column.
fn resize_handles(app: &mut App, ui: &mut egui::Ui, cols: &Cols, header_rect: Rect) {
    // (right_edge_x, which width to adjust)
    let edges: [(f32, fn(&mut super::ColWidths) -> &mut f32); 7] = [
        (cols.dir.0 + cols.dir.1, |c| &mut c.dir),
        (cols.action.0 + cols.action.1, |c| &mut c.action),
        (cols.profiles.0 + cols.profiles.1, |c| &mut c.profiles),
        (cols.scope.0 + cols.scope.1, |c| &mut c.scope),
        (cols.hits.0 + cols.hits.1, |c| &mut c.hits),
        (cols.last.0 + cols.last.1, |c| &mut c.last),
        (cols.listen.0 + cols.listen.1, |c| &mut c.listen),
    ];
    for (i, (x, sel)) in edges.into_iter().enumerate() {
        let hit = Rect::from_min_max(Pos2::new(x - 3.0, header_rect.top()), Pos2::new(x + 3.0, header_rect.bottom()));
        let resp = ui.interact(hit, ui.id().with(("colresize", i)), Sense::drag());
        if resp.hovered() || resp.dragged() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
            ui.painter().vline(x, header_rect.y_range(), Stroke::new(1.0, t::ACCENT));
        }
        if resp.dragged() {
            let w = sel(&mut app.col_w);
            *w = (*w + resp.drag_delta().x).clamp(30.0, 400.0);
        }
    }
}

use super::ROW_H;
use super::HEADER_H;

fn table_header(ui: &mut egui::Ui, app: &mut App, cols: &Cols) {
    let full = ui.max_rect();
    let rect = Rect::from_min_size(full.min, Vec2::new(full.width(), HEADER_H));
    let p = ui.painter();
    p.rect_filled(rect, 0.0, t::RAISED);
    let font = t::semibold(11.0);
    let c = t::SECONDARY;
    let y = rect.center().y;
    let th = |x: f32, s: &str, col: Color32| {
        ui.painter().text(Pos2::new(x + CELL_PAD, y), Align2::LEFT_CENTER, s, font.clone(), col);
    };
    let young = app.young_evidence_hours().is_some();
    let usage_hidden = app.phase == Phase::NeedsEnable;
    th(cols.name.0, "Rule", c);
    th(cols.dir.0, "Dir", c);
    th(cols.action.0, "Action", c);
    th(cols.profiles.0, "Profiles", c);
    th(cols.scope.0, "Scope", c);
    if usage_hidden {
        ui.painter().text(
            Pos2::new(cols.hits.0 + CELL_PAD, y),
            Align2::LEFT_CENTER,
            "Hits · Last seen · Apps",
            font.clone(),
            t::CB_EMPTY_BORDER,
        );
        ui.painter().text(
            Pos2::new(cols.hits.0 + 128.0, y),
            Align2::LEFT_CENTER,
            "requires auditing",
            t::italic(11.0),
            t::CB_EMPTY_BORDER,
        );
    } else {
        // hits header: clickable sort + young-evidence tint (leave 1px at the
        // bottom so the header's bottom border still shows through the fill)
        let hits_rect = Rect::from_min_size(Pos2::new(cols.hits.0, rect.top()), Vec2::new(cols.hits.1, HEADER_H));
        let last_rect = Rect::from_min_size(Pos2::new(cols.last.0, rect.top()), Vec2::new(cols.last.1, HEADER_H));
        if young {
            let inset = |r: Rect| Rect::from_min_max(r.min, Pos2::new(r.right(), r.bottom() - 1.0));
            ui.painter().rect_filled(inset(hits_rect), 0.0, t::ADVISORY_BG);
            ui.painter().rect_filled(inset(last_rect), 0.0, t::ADVISORY_BG);
        }
        let hits_col = if young { t::ADVISORY_HEADER } else { t::INK };
        th(cols.hits.0, "Hits A / B", hits_col);
        // sort/young indicator triangle after the label
        let hg = ui.painter().layout_no_wrap("Hits A / B".into(), font.clone(), hits_col);
        let ax = cols.hits.0 + CELL_PAD + hg.size().x + 7.0;
        if young {
            glyph::warn_tri(ui.painter(), Pos2::new(ax, y), 8.0, t::ADVISORY);
        } else if app.sort == Sort::Hits {
            if app.sort_asc {
                glyph::tri_up(ui.painter(), Pos2::new(ax, y), 8.0, hits_col);
            } else {
                glyph::tri_down(ui.painter(), Pos2::new(ax, y), 8.0, hits_col);
            }
        }
        th(cols.last.0, "Last seen", if young { t::ADVISORY_HEADER } else { c });
        th(cols.apps.0, "Apps observed", c);
        th(cols.listen.0, "Listening now", c);
        // sort interactions
        if ui.interact(hits_rect, ui.id().with("sort_hits"), Sense::click()).clicked() {
            toggle_sort(app, Sort::Hits);
        }
        if ui.interact(last_rect, ui.id().with("sort_last"), Sense::click()).clicked() {
            toggle_sort(app, Sort::LastSeen);
        }
    }
    let name_rect = Rect::from_min_size(Pos2::new(cols.name.0, rect.top()), Vec2::new(cols.name.1, HEADER_H));
    if ui.interact(name_rect, ui.id().with("sort_name"), Sense::click()).clicked() {
        toggle_sort(app, Sort::Name);
    }
    // column separators
    for x in [cols.name.0, cols.dir.0, cols.action.0, cols.profiles.0, cols.scope.0, cols.hits.0, cols.last.0, cols.apps.0, cols.listen.0] {
        ui.painter().vline(x, rect.y_range(), Stroke::new(1.0, t::BORDER_LIGHT));
    }
    // resize handles on the fixed-column right edges
    resize_handles(app, ui, cols, rect);
    // bottom border last, full width and on top of the yellow fills
    ui.painter().hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, t::CONTROL_BORDER));
}

fn toggle_sort(app: &mut App, key: Sort) {
    if app.sort == key {
        app.sort_asc = !app.sort_asc;
    } else {
        app.sort = key;
        app.sort_asc = matches!(key, Sort::Name); // names A→Z, counts/time high→low
    }
}

fn row(app: &mut App, ui: &mut egui::Ui, ri: usize, rect: Rect, cols: &Cols, resp: egui::Response) {
    // apply-phase status for this rule, if any
    let apply_status = app.apply.as_ref().and_then(|a| {
        let r = &app.rows[ri];
        if !(r.pending() || a.results.contains_key(&r.rule.name)) {
            return None;
        }
        Some(match a.results.get(&r.rule.name) {
            Some(Ok(())) => RowApply::Done,
            Some(Err(e)) => RowApply::Failed(e.clone()),
            None if a.current.as_deref() == Some(r.rule.name.as_str()) => RowApply::Active(r.target_enabled),
            None if !a.finished => RowApply::Queued,
            None => RowApply::Pending,
        })
    });

    let r = &app.rows[ri];
    let selected = app.selected == Some(ri);
    let pending = r.pending();
    let saved_on = r.rule.is_enabled();
    let dimmed = !saved_on && !pending;
    let failed = matches!(apply_status, Some(RowApply::Failed(_)));

    // background
    let bg = if failed {
        t::FAIL_BG
    } else if selected {
        t::SELECTED_ROW
    } else if pending {
        t::ACCENT_TINT
    } else if resp.hovered() {
        t::HOVER_WASH
    } else {
        Color32::WHITE
    };
    let p = ui.painter();
    p.rect_filled(rect, 0.0, bg);
    p.hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, t::ROW_BORDER));
    // faint column separators, aligned with the header's
    let sep = Stroke::new(1.0, t::ROW_BORDER);
    for x in [cols.name.0, cols.dir.0, cols.action.0, cols.profiles.0, cols.scope.0, cols.hits.0, cols.last.0, cols.apps.0, cols.listen.0] {
        p.vline(x, rect.y_range(), sep);
    }
    // edge bar
    if failed {
        p.rect_filled(Rect::from_min_size(rect.min, Vec2::new(3.0, rect.height())), 0.0, t::DESTRUCTIVE);
    } else if pending {
        p.rect_filled(Rect::from_min_size(rect.min, Vec2::new(3.0, rect.height())), 0.0, t::ACCENT);
    }

    let queued_dim = matches!(apply_status, Some(RowApply::Queued));
    let text_col = if dimmed || queued_dim { t::DISABLED } else { t::INK };

    // checkbox — indeterminate when the rule stays on but its profile scope
    // was narrowed
    let partial = r.target_enabled
        && !r.target_profiles.is_empty()
        && r.target_profiles != r.orig_profiles();
    let cb_rect = Rect::from_center_size(Pos2::new(cols.check + 17.0, rect.center().y), Vec2::splat(13.0));
    draw_checkbox(ui.painter(), cb_rect, saved_on, pending, r.target_enabled, partial);
    let cb_resp = ui.interact(cb_rect.expand(3.0), ui.id().with(("cb", ri)), Sense::click());

    // name (+ flag)
    let name_font = if pending && !dimmed { t::medium(12.0) } else { t::sans(12.0) };
    let flag_pad = if !r.flags.is_empty() { 16.0 } else { 0.0 };
    let name_rect = Rect::from_min_size(Pos2::new(cols.name.0, rect.top()), Vec2::new(cols.name.1 - CELL_PAD - flag_pad, rect.height()));
    cell_text(ui.painter(), name_rect, &r.rule.display_name, name_font, text_col, CELL_PAD);
    if !r.flags.is_empty() {
        // width of name for flag placement
        let g = ui.painter().layout_no_wrap(r.rule.display_name.clone(), t::sans(12.0), t::ADVISORY);
        let fx = (cols.name.0 + CELL_PAD + g.size().x + 8.0).min(cols.name.0 + cols.name.1 - 10.0);
        glyph::warn_tri(ui.painter(), Pos2::new(fx, rect.center().y), 9.0, t::ADVISORY);
    }

    // dir / action
    cell_text(ui.painter(), col_rect(cols.dir, rect), dir_short(&r.rule.direction), t::sans(11.5), if dimmed { t::DISABLED } else { t::TERTIARY }, CELL_PAD);
    let act_col = if dimmed { t::DISABLED } else if r.rule.action.eq_ignore_ascii_case("block") { t::BLOCK } else { t::INK };
    cell_text(ui.painter(), col_rect(cols.action, rect), act_short(&r.rule.action), t::sans(12.0), act_col, CELL_PAD);

    // profiles chips — clickable to toggle a profile off/on for this rule
    let orig = r.orig_profiles();
    let target = r.target_profiles;
    let mut clicked_profile: Option<u8> = None;
    let mut cx = cols.profiles.0 + CELL_PAD;
    let editable = app.apply.is_none() && app.phase == Phase::Ready;
    for (bit, present, kept, label) in [
        (0u8, orig.domain, target.domain, "Domain"),
        (1, orig.private, target.private, "Private"),
        (2, orig.public, target.public, "Public"),
    ] {
        if !present {
            continue;
        }
        let (w, resp) = interactive_chip(ui, Pos2::new(cx, rect.center().y - 7.5), label, kept, editable, (ri, bit));
        cx += w;
        if resp.map_or(false, |r| r.clicked()) {
            clicked_profile = Some(bit);
        }
    }

    // scope (mono)
    cell_text(ui.painter(), Rect::from_min_size(Pos2::new(cols.scope.0, rect.top()), Vec2::new(cols.scope.1 - CELL_PAD, rect.height())), &listeners::scope_summary(&r.rule), t::mono(11.0), if dimmed { t::DISABLED } else { t::SECONDARY }, CELL_PAD);

    // usage columns (hidden on first run)
    if app.phase == Phase::NeedsEnable {
        ui.painter().text(Pos2::new(cols.hits.0 + CELL_PAD, rect.center().y), Align2::LEFT_CENTER, "—  ·  —  ·  —", t::sans(11.0), t::FIRSTRUN_DASH);
    } else if let Some(st) = &apply_status {
        // apply status occupies the last-seen/apps span
        let (txt, col) = st.label(r);
        ui.painter().text(Pos2::new(cols.hits.0 + CELL_PAD, rect.center().y), Align2::LEFT_CENTER, hits_ab(r).0, t::mono(11.5), t::DISABLED);
        ui.painter().text(Pos2::new(cols.last.0 + CELL_PAD, rect.center().y), Align2::LEFT_CENTER, &txt, if matches!(st, RowApply::Active(_)) { t::mono_medium(11.0) } else { t::sans(11.0) }, col);
    } else {
        // hits A / B (with per-profile split on hover)
        let (a, b, azero, bnz) = hits_ab_parts(r);
        let hx = cols.hits.0 + CELL_PAD;
        let ga = ui.painter().layout_no_wrap(a.clone(), t::mono(11.5), if azero { t::DISABLED } else { t::INK });
        let wa = ga.size().x;
        ui.painter().galley(Pos2::new(hx, rect.center().y - ga.size().y / 2.0), ga, if azero { t::DISABLED } else { t::INK });
        ui.painter().text(Pos2::new(hx + wa + 4.0, rect.center().y), Align2::LEFT_CENTER, "/", t::mono(11.5), t::HAIRLINE_TEXT);
        ui.painter().text(Pos2::new(hx + wa + 12.0, rect.center().y), Align2::LEFT_CENTER, &b, t::mono(11.5), if bnz { t::BLOCK } else { t::DISABLED });
        if let Some(u) = &r.usage {
            if !u.by_profile.is_empty() {
                let hits_rect = col_rect(cols.hits, rect);
                if ui.rect_contains_pointer(hits_rect) {
                    egui::show_tooltip_at_pointer(ui.ctx(), ui.layer_id(), egui::Id::new(("hits_tt", ri)), |ui| {
                        ui.label(egui::RichText::new("Hits by profile (allow / block)").font(t::semibold(11.0)).color(t::INK));
                        for (prof, al, bl) in &u.by_profile {
                            ui.label(egui::RichText::new(format!("{prof}:  {} / {}", t::fmt_thousands(*al), t::fmt_thousands(*bl))).font(t::mono(11.0)).color(t::SECONDARY));
                        }
                    });
                }
            }
        }

        // last seen
        let (last_txt, last_col) = match r.usage.as_ref().and_then(|u| u.last_seen.as_deref()) {
            Some(ls) => (time_util::relative(ls), t::SECONDARY),
            None => ("never".to_string(), t::DISABLED),
        };
        cell_text(ui.painter(), col_rect(cols.last, rect), &last_txt, t::sans(11.0), last_col, CELL_PAD);

        // apps observed
        let apps = apps_summary(r);
        let (apps_txt, apps_col) = if apps.is_empty() { ("—".to_string(), t::HAIRLINE_TEXT) } else { (apps, t::SECONDARY) };
        cell_text(ui.painter(), Rect::from_min_size(Pos2::new(cols.apps.0, rect.top()), Vec2::new(cols.apps.1 - CELL_PAD, rect.height())), &apps_txt, t::sans(11.0), apps_col, CELL_PAD);

        // listening chip
        if let Some(first) = r.listening.first() {
            draw_listen_chip(ui.painter(), Pos2::new(cols.listen.0 + CELL_PAD, rect.center().y - 8.5), first);
        } else {
            ui.painter().text(Pos2::new(cols.listen.0 + CELL_PAD, rect.center().y), Align2::LEFT_CENTER, "—", t::sans(11.0), t::HAIRLINE_TEXT);
        }
    }

    // tooltip built while the immutable borrow is live, so mutations below
    // don't overlap it
    let tip = format!(
        "{}\n{}",
        r.rule.description.as_deref().filter(|d| !d.trim().is_empty()).unwrap_or("(no description)"),
        listeners::scope_summary(&r.rule)
    );

    // interactions
    if let Some(bit) = clicked_profile {
        let p = &mut app.rows[ri].target_profiles;
        match bit {
            0 => p.domain = !p.domain,
            1 => p.private = !p.private,
            _ => p.public = !p.public,
        }
    } else if cb_resp.clicked() && app.apply.is_none() {
        app.rows[ri].target_enabled = !app.rows[ri].target_enabled;
    } else if resp.clicked() {
        app.selected = if selected { None } else { Some(ri) };
    }
    if resp.hovered() {
        resp.on_hover_text(tip);
    }
}

enum RowApply {
    Queued,
    Pending,
    Active(bool),
    Done,
    Failed(String),
}

impl RowApply {
    fn label(&self, _r: &super::RuleRow) -> (String, Color32) {
        match self {
            RowApply::Queued => ("queued".into(), t::TERTIARY),
            RowApply::Pending => ("pending".into(), t::TERTIARY),
            RowApply::Active(target) => (if *target { "applying…".into() } else { "disabling…".into() }, t::ACCENT),
            RowApply::Done => ("applied ✓".into(), t::LIVE_TEXT),
            RowApply::Failed(e) => (format!("failed — {}", short_err(e)), t::DESTRUCTIVE),
        }
    }
}

fn short_err(e: &str) -> String {
    let line = e.lines().next().unwrap_or(e);
    if line.len() > 60 { format!("{}…", &line[..60]) } else { line.to_string() }
}

fn col_rect(c: (f32, f32), row: Rect) -> Rect {
    Rect::from_min_size(Pos2::new(c.0, row.top()), Vec2::new(c.1, row.height()))
}

fn dir_short(d: &str) -> &str {
    if d.eq_ignore_ascii_case("inbound") { "In" } else if d.eq_ignore_ascii_case("outbound") { "Out" } else { d }
}
fn act_short(a: &str) -> &str {
    if a.eq_ignore_ascii_case("allow") { "Allow" } else if a.eq_ignore_ascii_case("block") { "Block" } else { a }
}

fn hits_ab(r: &super::RuleRow) -> (&'static str, &'static str) {
    let _ = r;
    ("", "")
}
fn hits_ab_parts(r: &super::RuleRow) -> (String, String, bool, bool) {
    match &r.usage {
        Some(u) => (
            t::fmt_thousands(u.allow_count),
            t::fmt_thousands(u.block_count),
            u.allow_count == 0,
            u.block_count > 0,
        ),
        None => ("0".into(), "0".into(), true, false),
    }
}

fn apps_summary(r: &super::RuleRow) -> String {
    if r.seen_apps.is_empty() {
        return String::new();
    }
    let short: Vec<&str> = r.seen_apps.iter().map(|s| s.split(" (").next().unwrap_or(s)).collect();
    if short.len() <= 2 {
        short.join(", ")
    } else {
        format!("{}, {} +{}", short[0], short[1], short.len() - 2)
    }
}

enum CbMark {
    Check,
    Dash,
    None,
}

/// `partial` = the rule stays enabled but its profile scope was narrowed —
/// drawn as an indeterminate dash, the standard tri-state affordance.
fn draw_checkbox(p: &egui::Painter, rect: Rect, saved_on: bool, pending: bool, target: bool, partial: bool) {
    let (border, fill, mark, mark_col) = if partial {
        (t::ACCENT, Color32::WHITE, CbMark::Dash, t::ACCENT)
    } else if pending {
        if target {
            (t::ACCENT, t::ACCENT, CbMark::Check, Color32::WHITE)
        } else {
            (t::ACCENT, Color32::WHITE, CbMark::None, t::INK)
        }
    } else if saved_on {
        (t::CB_SAVED_BORDER, Color32::WHITE, CbMark::Check, t::INK)
    } else {
        (t::CB_EMPTY_BORDER, Color32::WHITE, CbMark::None, t::INK)
    };
    p.rect(rect, 0.0, fill, Stroke::new(1.5, border));
    match mark {
        CbMark::Check => glyph::check(p, rect.center(), 9.0, mark_col),
        CbMark::Dash => {
            p.hline(rect.left() + 3.0..=rect.right() - 3.0, rect.center().y, Stroke::new(2.0, mark_col));
        }
        CbMark::None => {}
    }
}

fn draw_listen_chip(p: &egui::Painter, top_left: Pos2, text: &str) {
    let font = t::mono(10.5);
    let galley = p.layout_no_wrap(text.to_string(), font, t::LIVE_TEXT);
    let w = galley.size().x + 14.0 + 11.0;
    let rect = Rect::from_min_size(top_left, Vec2::new(w, 17.0));
    p.rect(rect, 0.0, t::LIVE_BG, Stroke::new(1.0, t::LIVE_BORDER));
    p.circle_filled(Pos2::new(rect.left() + 7.0, rect.center().y), 3.0, t::LIVE);
    p.galley(Pos2::new(rect.left() + 14.0, rect.center().y - galley.size().y / 2.0), galley, t::LIVE_TEXT);
}

fn empty_state(app: &mut App, ui: &mut egui::Ui) {
    let full = ui.max_rect();
    let area = Rect::from_min_max(Pos2::new(full.left(), full.top() + HEADER_H), full.max);
    let mut child = ui.child_ui(area, egui::Layout::top_down(egui::Align::Center), None);
    child.add_space(40.0);
    let mut msg = egui::text::LayoutJob::default();
    msg.halign = egui::Align::Center;
    msg.append("No rules match ", 0.0, fmt(t::sans(12.5), t::SECONDARY));
    if !app.filter_text.is_empty() {
        msg.append(&format!("“{}” ", app.filter_text), 0.0, fmt(t::semibold(12.5), t::SECONDARY));
    }
    msg.append("with the current filters.", 0.0, fmt(t::sans(12.5), t::SECONDARY));
    child.label(msg);
    child.add_space(4.0);
    let hidden = app.rows.len();
    child.label(egui::RichText::new(format!("{hidden} rules hidden by the active filters.")).font(t::sans(11.5)).color(t::FAINT));
    child.add_space(10.0);
    child.horizontal(|ui| {
        ui.add_space((ui.available_width() - 240.0).max(0.0) / 2.0);
        if flat_button(ui, "Clear text").clicked() {
            app.filter_text.clear();
        }
        ui.add_space(10.0);
        if flat_button(ui, "Clear all filters").clicked() {
            app.filter_text.clear();
            app.only_enabled = false;
            app.only_zero_hit = false;
            app.only_flagged = false;
            app.show_domain = true;
            app.show_private = true;
            app.show_public = true;
        }
    });
}

// ---- detail panel ----

fn detail_panel(app: &mut App, ctx: &egui::Context) {
    let Some(ri) = app.selected else { return };
    egui::SidePanel::right("detail")
        .exact_width(300.0)
        .resizable(false)
        .frame(egui::Frame::none().fill(t::RAISED))
        .show(ctx, |ui| {
            ui.painter().vline(ui.max_rect().left(), ui.max_rect().y_range(), Stroke::new(1.0, t::BORDER));
            let r = &app.rows[ri];
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.add_space(14.0);
                    ui.label(egui::RichText::new(&r.rule.display_name).font(t::semibold(13.0)).color(t::INK));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        ui.add_space(14.0);
                        let (r, resp) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::click());
                        glyph::cross(ui.painter(), r.center(), 10.0, if resp.hovered() { t::INK } else { t::FAINT });
                        if resp.clicked() {
                            app.selected = None;
                        }
                    });
                });
                if let Some(desc) = r.rule.description.as_deref().filter(|d| !d.trim().is_empty()) {
                    ui.add_space(6.0);
                    pad_label(ui, egui::RichText::new(desc).font(t::italic(11.5)).color(t::SECONDARY));
                }
                ui.add_space(12.0);
                section_sep(ui);

                // advisory blocks
                for f in &r.flags {
                    advisory_block(ui, f);
                    section_sep(ui);
                }

                // key-value grid
                ui.add_space(10.0);
                kv(ui, "Rule ID", &r.rule.name, true);
                if let Some(g) = r.rule.group.as_deref().filter(|s| !s.is_empty()) {
                    kv(ui, "Group", g, false);
                }
                kv(ui, "Program", r.rule.program.as_deref().unwrap_or("Any"), true);
                if let Some(s) = r.rule.service.as_deref().filter(|s| !s.is_empty() && *s != "Any") {
                    kv(ui, "Service", s, true);
                }
                kv(
                    ui,
                    "Ports",
                    &format!(
                        "{} local {} · remote {}",
                        r.rule.protocol.as_deref().unwrap_or("Any"),
                        r.rule.local_port.as_deref().unwrap_or("any"),
                        r.rule.remote_port.as_deref().unwrap_or("any")
                    ),
                    true,
                );
                kv(ui, "Remote addr", r.rule.remote_address.as_deref().unwrap_or("any"), true);
                ui.add_space(10.0);
                section_sep(ui);

                // evidence
                ui.add_space(12.0);
                if let Some(u) = &r.usage {
                    let total = u.allow_count + u.block_count;
                    pad_label(ui, egui::RichText::new(format!("Evidence — {} connections", t::fmt_thousands(total))).font(t::semibold(11.5)).color(t::INK));
                    // per-profile split
                    if !u.by_profile.is_empty() {
                        ui.add_space(6.0);
                        for (prof, al, bl) in &u.by_profile {
                            let color = match prof.as_str() {
                                "Domain" => t::CHIP_DOM.1,
                                "Private" => t::CHIP_PRV.1,
                                "Public" => t::CHIP_PUB.1,
                                _ => t::TERTIARY,
                            };
                            ui.horizontal(|ui| {
                                ui.add_space(14.0);
                                ui.label(egui::RichText::new(prof).font(t::semibold(11.0)).color(color));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.add_space(14.0);
                                    ui.label(egui::RichText::new(format!("{} / {}", t::fmt_thousands(*al), t::fmt_thousands(*bl))).font(t::mono(11.0)).color(t::SECONDARY));
                                });
                            });
                        }
                    }
                    ui.add_space(8.0);
                    for (path, hits) in u.apps.iter().take(8) {
                        ui.horizontal(|ui| {
                            ui.add_space(14.0);
                            let name = crate::app_identity::identify(path).friendly_name;
                            ui.label(egui::RichText::new(name).font(t::sans(11.0)).color(t::INK));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.add_space(14.0);
                                ui.label(egui::RichText::new(t::fmt_thousands(*hits)).font(t::mono(11.0)).color(t::SECONDARY));
                            });
                        });
                    }
                    ui.add_space(10.0);
                    let first = u.first_seen.as_deref().map(time_util::relative).unwrap_or_else(|| "—".into());
                    let last = u.last_seen.as_deref().map(time_util::relative).unwrap_or_else(|| "—".into());
                    pad_label(
                        ui,
                        egui::RichText::new(format!("First hit {first} · last {last} · {} distinct peers", u.distinct_peers))
                            .font(t::sans(11.0))
                            .color(t::SECONDARY),
                    );
                } else {
                    pad_label(ui, egui::RichText::new("No usage evidence collected yet.").font(t::italic(11.5)).color(t::FAINT));
                }
                ui.add_space(14.0);
            });
        });
}

fn pad_label(ui: &mut egui::Ui, text: egui::RichText) {
    ui.horizontal_wrapped(|ui| {
        ui.add_space(14.0);
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.set_max_width(272.0);
        ui.label(text);
    });
}

fn section_sep(ui: &mut egui::Ui) {
    ui.add_space(2.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter().hline(rect.x_range(), rect.center().y, Stroke::new(1.0, t::BORDER_LIGHT));
}

fn advisory_block(ui: &mut egui::Ui, f: &crate::model::BaselineFlag) {
    egui::Frame::none()
        .fill(t::ADVISORY_BG)
        .inner_margin(egui::Margin { left: 14.0, right: 14.0, top: 10.0, bottom: 10.0 })
        .show(ui, |ui| {
            ui.set_width(272.0);
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(Vec2::new(12.0, 12.0), Sense::hover());
                glyph::warn_tri(ui.painter(), r.center(), 9.0, t::ADVISORY);
                ui.label(egui::RichText::new(f.title).font(t::semibold(11.0)).color(t::ADVISORY_TEXT));
            });
            ui.add_space(3.0);
            ui.label(egui::RichText::new(f.advice).font(t::sans(11.0)).color(t::ADVISORY_TEXT));
        });
}

fn kv(ui: &mut egui::Ui, label: &str, value: &str, mono: bool) {
    ui.horizontal_top(|ui| {
        ui.add_space(14.0);
        ui.allocate_ui_with_layout(Vec2::new(86.0, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
            ui.label(egui::RichText::new(label).font(t::sans(11.0)).color(t::FAINT));
        });
        ui.allocate_ui_with_layout(Vec2::new(184.0, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
            let rt = if mono {
                egui::RichText::new(value).font(t::mono(10.5)).color(t::INK)
            } else {
                egui::RichText::new(value).font(t::sans(11.0)).color(t::INK)
            };
            ui.add(egui::Label::new(rt).wrap());
        });
    });
    ui.add_space(7.0);
}

// ---- evidence drawer ----

fn drawer(app: &mut App, ctx: &egui::Context) {
    if app.rows.is_empty() {
        return;
    }
    // Height fully owned by app.drawer_height (persists across frames); a
    // manual grab handle on the top edge adjusts it — no egui panel-memory
    // to fight, so it never snaps back.
    let panel_h = if app.drawer_open {
        app.drawer_height.clamp(90.0, 560.0) + 6.0 // +6 for the grab strip
    } else {
        28.0
    };
    egui::TopBottomPanel::bottom("drawer")
        .exact_height(panel_h)
        .resizable(false)
        .frame(egui::Frame::none().fill(t::RAISED))
        .show(ctx, |ui| {
            // resize grab strip (only when open)
            if app.drawer_open {
                let (grip, gresp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 6.0), Sense::drag());
                if gresp.hovered() || gresp.dragged() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);
                    ui.painter().hline(grip.x_range(), grip.center().y, Stroke::new(2.0, t::ACCENT_TINT_BORDER));
                } else {
                    ui.painter().hline(grip.x_range(), grip.center().y, Stroke::new(1.0, t::BORDER_LIGHT));
                }
                if gresp.dragged() {
                    // dragging up (negative dy) grows the drawer
                    app.drawer_height = (app.drawer_height - gresp.drag_delta().y).clamp(90.0, 560.0);
                }
            }

            // tab bar
            let bar = ui.allocate_exact_size(Vec2::new(ui.available_width(), 27.0), Sense::hover()).0;
            ui.painter().hline(bar.x_range(), bar.bottom() - 0.5, Stroke::new(1.0, t::BORDER_LIGHT));
            let mut x = bar.left();
            let tabs = [
                (Tab::Sockets, format!("Active listening sockets  {}", app.listeners.len())),
                (Tab::Unattributed, format!("Unattributed events  {}", app.unmatched.len())),
            ];
            for (tab, label) in tabs {
                let active = app.drawer_open && app.tab == tab;
                let g = ui.painter().layout_no_wrap(label.clone(), if active { t::semibold(11.5) } else { t::sans(11.5) }, if active { t::INK } else { t::SECONDARY });
                let w = g.size().x + 28.0;
                let tab_rect = Rect::from_min_size(Pos2::new(x, bar.top()), Vec2::new(w, 27.0));
                let hovered = ui.rect_contains_pointer(tab_rect);
                if active {
                    ui.painter().rect_filled(tab_rect, 0.0, Color32::WHITE);
                    ui.painter().hline(tab_rect.x_range(), tab_rect.top() + 1.0, Stroke::new(2.0, t::ACCENT));
                } else if hovered {
                    ui.painter().rect_filled(tab_rect, 0.0, t::HOVER_WASH);
                }
                ui.painter().vline(tab_rect.right(), tab_rect.y_range(), Stroke::new(1.0, t::BORDER_LIGHT));
                ui.painter().galley(tab_rect.center() - g.size() / 2.0, g, if active { t::INK } else { t::SECONDARY });
                let resp = ui.interact(tab_rect, ui.id().with(("tab", label)), Sense::click());
                if resp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                if resp.clicked() {
                    if app.drawer_open && app.tab == tab {
                        app.drawer_open = false;
                    } else {
                        app.drawer_open = true;
                        app.tab = tab;
                    }
                }
                x += w;
            }

            // collapse / expand control — a real button with hover
            let label = if app.drawer_open { "collapse" } else { "expand" };
            let lg = ui.painter().layout_no_wrap(label.to_string(), t::sans(11.0), t::SECONDARY);
            let ctrl_w = lg.size().x + 26.0;
            let ctrl = Rect::from_min_size(Pos2::new(bar.right() - ctrl_w, bar.top()), Vec2::new(ctrl_w, 27.0));
            let cresp = ui.interact(ctrl, ui.id().with("drawer_toggle"), Sense::click());
            let ccol = if cresp.hovered() { t::INK } else { t::SECONDARY };
            if cresp.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                ui.painter().rect_filled(ctrl, 0.0, t::HOVER_WASH);
            }
            if app.drawer_open {
                glyph::tri_down(ui.painter(), Pos2::new(ctrl.left() + 9.0, bar.center().y), 8.0, ccol);
            } else {
                glyph::tri_up(ui.painter(), Pos2::new(ctrl.left() + 9.0, bar.center().y), 8.0, ccol);
            }
            ui.painter().text(Pos2::new(ctrl.left() + 18.0, bar.center().y), Align2::LEFT_CENTER, label, t::sans(11.0), ccol);
            if cresp.clicked() {
                app.drawer_open = !app.drawer_open;
            }

            if app.drawer_open {
                let h = ui.available_height().max(40.0);
                ui.allocate_ui(Vec2::new(ui.available_width(), h), |ui| match app.tab {
                    Tab::Sockets => sockets_body(app, ui),
                    Tab::Unattributed => unattributed_body(app, ui),
                });
            }
        });
}

fn sockets_body(app: &App, ui: &mut egui::Ui) {
    let rect = ui.max_rect();
    ui.painter().rect_filled(rect, 0.0, Color32::WHITE);
    // header
    let hr = Rect::from_min_size(rect.min, Vec2::new(rect.width(), 22.0));
    let p = ui.painter();
    let hf = t::semibold(10.5);
    p.text(Pos2::new(rect.left() + PAGE, hr.center().y), Align2::LEFT_CENTER, "Proto", hf.clone(), t::FAINT);
    p.text(Pos2::new(rect.left() + PAGE + 60.0, hr.center().y), Align2::LEFT_CENTER, "Local address", hf.clone(), t::FAINT);
    p.text(Pos2::new(rect.left() + PAGE + 260.0, hr.center().y), Align2::LEFT_CENTER, "Process", hf.clone(), t::FAINT);
    p.text(Pos2::new(rect.left() + PAGE + 520.0, hr.center().y), Align2::LEFT_CENTER, "Matched rule", hf, t::FAINT);
    p.hline(rect.x_range(), hr.bottom(), Stroke::new(1.0, t::ROW_BORDER));

    let mut list: Vec<&Listener> = app.listeners.iter().collect();
    list.sort_by_key(|l| (l.proto.clone(), l.local_port));
    let inner = Rect::from_min_max(Pos2::new(rect.left(), hr.bottom()), rect.max);
    let mut child = ui.child_ui(inner, egui::Layout::top_down(egui::Align::Min), None);
    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(&mut child, |ui| {
        for l in list {
            let (rr, _) = ui.allocate_exact_size(Vec2::new(rect.width(), 20.0), Sense::hover());
            let p = ui.painter();
            let y = rr.center().y;
            p.text(Pos2::new(rect.left() + PAGE, y), Align2::LEFT_CENTER, &l.proto, t::mono(11.0), t::INK);
            p.text(Pos2::new(rect.left() + PAGE + 60.0, y), Align2::LEFT_CENTER, format!("{}:{}", l.local_address, l.local_port), t::mono(11.0), t::INK);
            let proc = if l.process_name.is_empty() { format!("pid {}", l.pid) } else { format!("{} (pid {})", l.process_name, l.pid) };
            p.text(Pos2::new(rect.left() + PAGE + 260.0, y), Align2::LEFT_CENTER, proc, t::mono(11.0), t::INK);
            let matched = matched_rule(app, l);
            let (txt, col) = match matched {
                Some(name) => (name, t::INK),
                None if l.local_address.starts_with("127.") || l.local_address == "::1" => ("loopback — no rule required".to_string(), t::DISABLED),
                None => ("—".to_string(), t::HAIRLINE_TEXT),
            };
            p.text(Pos2::new(rect.left() + PAGE + 520.0, y), Align2::LEFT_CENTER, txt, t::sans(11.0), col);
            p.hline(rect.x_range(), rr.bottom() - 0.5, Stroke::new(1.0, t::CHROME));
        }
    });
}

fn matched_rule(app: &App, l: &Listener) -> Option<String> {
    let key = format!("{}:{}", if l.process_name.is_empty() { format!("pid{}", l.pid) } else { l.process_name.clone() }, l.local_port);
    app.rows
        .iter()
        .find(|r| r.rule.is_enabled() && r.listening.iter().any(|e| e == &key))
        .map(|r| r.rule.display_name.clone())
}

fn unattributed_body(app: &App, ui: &mut egui::Ui) {
    let rect = ui.max_rect();
    ui.painter().rect_filled(rect, 0.0, Color32::WHITE);
    // permanent explainer
    let ex = Rect::from_min_size(rect.min, Vec2::new(rect.width(), 26.0));
    ui.painter().rect_filled(ex, 0.0, t::RAISED);
    ui.painter().hline(ex.x_range(), ex.bottom(), Stroke::new(1.0, t::ROW_BORDER));
    let mut job = egui::text::LayoutJob::default();
    job.wrap.max_width = rect.width() - 2.0 * PAGE;
    job.append("Traffic that Windows blocked by default policy — it matched no rule at all. Port scans and stray broadcasts land here. This is normal, not an error.", 0.0, fmt(t::italic(11.0), t::SECONDARY));
    ui.painter().galley(Pos2::new(rect.left() + PAGE, ex.center().y - 7.0), ui.painter().layout_job(job), t::SECONDARY);

    let inner = Rect::from_min_max(Pos2::new(rect.left(), ex.bottom()), rect.max);
    let mut child = ui.child_ui(inner, egui::Layout::top_down(egui::Align::Min), None);
    if app.unmatched.is_empty() {
        child.centered_and_justified(|ui| {
            ui.label(egui::RichText::new("Nothing yet — unattributed events appear once auditing is enabled.").font(t::sans(11.5)).color(t::CB_EMPTY_BORDER));
        });
        return;
    }
    egui::ScrollArea::vertical().auto_shrink([false; 2]).show(&mut child, |ui| {
        for u in app.unmatched.iter().take(100) {
            let (rr, _) = ui.allocate_exact_size(Vec2::new(rect.width(), 20.0), Sense::hover());
            let p = ui.painter();
            let y = rr.center().y;
            p.text(Pos2::new(rect.left() + PAGE, y), Align2::LEFT_CENTER, &u.filter_name, t::sans(11.0), t::INK);
            p.text(Pos2::new(rect.left() + PAGE + 320.0, y), Align2::LEFT_CENTER, format!("filter {}", u.filter_id), t::mono(10.5), t::TERTIARY);
            p.text(Pos2::new(rect.left() + PAGE + 470.0, y), Align2::LEFT_CENTER, format!("{} allow / {} block", u.usage.allow_count, u.usage.block_count), t::mono(10.5), t::SECONDARY);
            p.hline(rect.x_range(), rr.bottom() - 0.5, Stroke::new(1.0, t::CHROME));
        }
    });
}

// ---- footer ----

fn footer(app: &mut App, ctx: &egui::Context) {
    let (dis, en, scope) = app.pending_counts();
    let has_pending = dis + en + scope > 0;
    let running = app.apply_running();
    let partial = app.apply_partial_failure();
    if !has_pending && !running && !partial {
        return;
    }
    let (fill, border) = if partial {
        (t::FAIL_BG, t::FAIL_BORDER)
    } else {
        (t::ACCENT_TINT, t::ACCENT_TINT_BORDER)
    };
    egui::TopBottomPanel::bottom("footer")
        .exact_height(44.0)
        .frame(egui::Frame::none().fill(fill).inner_margin(egui::Margin::symmetric(PAGE, 0.0)))
        .show(ctx, |ui| {
            ui.painter().hline(ui.max_rect().expand2(Vec2::new(PAGE, 0.0)).x_range(), ui.max_rect().top(), Stroke::new(1.0, border));
            if running {
                footer_running(app, ui);
            } else if partial {
                footer_partial(app, ui);
            } else {
                footer_pending(app, ui, dis, en, scope, ctx);
            }
        });
}

fn footer_pending(app: &mut App, ui: &mut egui::Ui, dis: usize, en: usize, scope: usize, ctx: &egui::Context) {
    ui.horizontal_centered(|ui| {
        let total = dis + en + scope;
        let mut job = egui::text::LayoutJob::default();
        job.append(&format!("{total} pending change{}", if total == 1 { "" } else { "s" }), 0.0, fmt(t::semibold(12.0), t::INK));
        job.append("  —  ", 0.0, fmt(t::sans(12.0), t::SECONDARY));
        let mut parts: Vec<(String, egui::Color32)> = Vec::new();
        if dis > 0 { parts.push((format!("{dis} to disable"), t::BLOCK)); }
        if en > 0 { parts.push((format!("{en} to enable"), t::ENABLE_GREEN)); }
        if scope > 0 { parts.push((format!("{scope} profile change{}", if scope == 1 { "" } else { "s" }), t::ACCENT)); }
        for (i, (text, col)) in parts.iter().enumerate() {
            if i > 0 {
                job.append(" · ", 0.0, fmt(t::sans(12.0), t::SECONDARY));
            }
            job.append(text, 0.0, fmt(t::sans(12.0), *col));
        }
        ui.label(job);
        ui.add_space(14.0);
        if link(ui, "Revert all", t::ACCENT).clicked() {
            app.revert_all();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let label = format!("Apply {total} change{}…", if total == 1 { "" } else { "s" });
            if primary_button(ui, &label, t::ACCENT).clicked() {
                app.confirm_open = true;
            }
            ui.add_space(14.0);
            ui.label(egui::RichText::new("A restorable policy backup is written before any change.").font(t::italic(11.0)).color(t::SECONDARY));
        });
    });
    let _ = ctx;
}

fn footer_running(app: &mut App, ui: &mut egui::Ui) {
    let (total, done, current, backup, backup_failed) = {
        let a = app.apply.as_ref().unwrap();
        (a.total, a.done, a.current.clone(), a.backup.clone(), a.backup_failed.clone())
    };
    let cur_name = current
        .as_ref()
        .and_then(|cur| app.rows.iter().find(|r| &r.rule.name == cur).map(|r| r.rule.display_name.clone()))
        .or_else(|| current.clone())
        .unwrap_or_default();
    ui.horizontal_centered(|ui| {
        let (track, _) = ui.allocate_exact_size(Vec2::new(200.0, 6.0), Sense::hover());
        ui.painter().rect_filled(track, 0.0, t::PROGRESS_TRACK);
        let frac = if total > 0 { done as f32 / total as f32 } else { 0.0 };
        ui.painter().rect_filled(Rect::from_min_size(track.min, Vec2::new(track.width() * frac, track.height())), 0.0, t::ACCENT);
        ui.add_space(14.0);
        let step = (done + if current.is_some() { 1 } else { 0 }).min(total).max(1);
        let mut job = egui::text::LayoutJob::default();
        job.append(&format!("Applying {step} of {total} "), 0.0, fmt(t::semibold(12.0), t::INK));
        if !cur_name.is_empty() {
            job.append(&format!("— {cur_name}"), 0.0, fmt(t::sans(12.0), t::INK));
        }
        ui.label(job);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if flat_button(ui, "Stop after current").clicked() {
                if let Some(a) = &mut app.apply {
                    a.stop_requested = true;
                }
            }
            ui.add_space(14.0);
            if let Some(b) = &backup {
                ui.label(egui::RichText::new(format!("Backup written ✓  {}", b.rsplit(['\\', '/']).next().unwrap_or(b))).font(t::sans(11.0)).color(t::SECONDARY));
            } else if let Some(e) = &backup_failed {
                ui.label(egui::RichText::new(format!("Backup failed: {}", short_err(e))).font(t::sans(11.0)).color(t::DESTRUCTIVE));
            }
        });
    });
}

fn footer_partial(app: &mut App, ui: &mut egui::Ui) {
    let (ok, fail) = {
        let a = app.apply.as_ref().unwrap();
        (a.results.values().filter(|r| r.is_ok()).count(), a.results.values().filter(|r| r.is_err()).count())
    };
    ui.horizontal_centered(|ui| {
        let mut job = egui::text::LayoutJob::default();
        job.append(&format!("{ok} of {} applied.", ok + fail), 0.0, fmt(t::semibold(12.0), t::DESTRUCTIVE_DARK));
        job.append(&format!(" {fail} failed and {} still pending — nothing was rolled back.", if fail == 1 { "is" } else { "are" }), 0.0, fmt(t::sans(12.0), t::DESTRUCTIVE_DARK));
        ui.label(job);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if primary_button(ui, &format!("Retry {fail} failed"), t::ACCENT).clicked() {
                let ctx = ui.ctx().clone();
                app.apply = None;
                app.start_apply(&ctx);
            }
            ui.add_space(8.0);
            if flat_button(ui, "Dismiss").clicked() {
                // revert intent on failed rows back to saved, clear apply
                if let Some(a) = app.apply.take() {
                    for (name, res) in a.results {
                        if res.is_err() {
                            if let Some(r) = app.rows.iter_mut().find(|r| r.rule.name == name) {
                                r.target_enabled = r.rule.is_enabled();
                            }
                        }
                    }
                }
            }
            ui.add_space(14.0);
            ui.label(egui::RichText::new("Backup retained.").font(t::italic(11.0)).color(t::SECONDARY));
        });
    });
}

fn primary_button(ui: &mut egui::Ui, label: &str, fill: Color32) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(label.to_string(), t::semibold(12.0), Color32::WHITE);
    let size = Vec2::new(galley.size().x + 36.0, galley.size().y + 14.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let f = if resp.is_pointer_button_down_on() {
        fill.gamma_multiply(0.85)
    } else if resp.hovered() {
        fill.gamma_multiply(1.12)
    } else {
        fill
    };
    if resp.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    ui.painter().rect_filled(rect, 0.0, f);
    ui.painter().galley(rect.center() - galley.size() / 2.0, galley, Color32::WHITE);
    resp
}

// ---- confirm modal ----

fn confirm_modal(app: &mut App, ctx: &egui::Context) {
    let plan = app.planned_changes();
    let total = plan.len();
    let (dis, en, scope) = app.pending_counts();
    // scrim
    egui::Area::new("scrim".into()).order(egui::Order::Background).show(ctx, |ui| {
        let r = ctx.screen_rect();
        ui.painter().rect_filled(r, 0.0, Color32::from_rgba_unmultiplied(44, 62, 80, 102));
    });
    let mut open = true;
    // list gets up to ~55% of the window height before it scrolls
    let list_max = (ctx.screen_rect().height() * 0.55).clamp(200.0, 520.0);
    egui::Window::new("confirm")
        .title_bar(false)
        .collapsible(false)
        .resizable(false)
        .fixed_size(Vec2::new(680.0, 0.0))
        .anchor(Align2::CENTER_TOP, Vec2::new(0.0, 70.0))
        .frame(egui::Frame::none().fill(Color32::WHITE).stroke(Stroke::new(1.0, t::CONTROL_BORDER)))
        .show(ctx, |ui| {
            // title
            ui.add_space(16.0);
            pad20(ui, |ui| {
                ui.label(egui::RichText::new(format!("Apply {total} change{} to Windows Firewall?", if total == 1 { "" } else { "s" })).font(t::semibold(15.0)).color(t::INK));
                ui.add_space(4.0);
                ui.label(egui::RichText::new(format!("{} · policy will change immediately for new connections", app.ctx_info.hostname)).font(t::sans(12.0)).color(t::SECONDARY));
            });
            ui.add_space(12.0);
            section_sep(ui);
            ui.add_space(12.0);

            // change rows (scrollable — a big batch shouldn't blow the modal)
            pad20(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(list_max)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        for c in &plan {
                            change_row(app, ui, c);
                        }
                    });
            });

            // backup box
            ui.add_space(12.0);
            pad20(ui, |ui| {
                egui::Frame::none()
                    .fill(t::BACKUP_BG)
                    .stroke(Stroke::new(1.0, t::BACKUP_BORDER))
                    .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                    .show(ui, |ui| {
                        ui.horizontal_top(|ui| {
                            ui.spacing_mut().item_spacing.x = 8.0;
                            let (r, _) = ui.allocate_exact_size(Vec2::new(13.0, 14.0), Sense::hover());
                            glyph::check(ui.painter(), r.center(), 11.0, t::LIVE_TEXT);
                            let mut job = egui::text::LayoutJob::default();
                            job.wrap.max_width = 500.0;
                            job.append("A restorable backup of the full firewall policy is written ", 0.0, fmt(t::sans(11.5), t::BACKUP_TEXT));
                            job.append("before", 0.0, fmt(t::semibold(11.5), t::BACKUP_TEXT));
                            job.append(" any change, to ", 0.0, fmt(t::sans(11.5), t::BACKUP_TEXT));
                            job.append("%ProgramData%\\firebreak\\backups\\", 0.0, fmt(t::mono(10.5), t::BACKUP_TEXT));
                            job.append(" — restore anytime from Settings → Backups.", 0.0, fmt(t::sans(11.5), t::BACKUP_TEXT));
                            ui.label(job);
                        });
                    });
            });
            ui.add_space(12.0);
            section_sep(ui);

            // footer buttons
            ui.add_space(12.0);
            pad20(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Changes are also written to the audit log.").font(t::sans(11.0)).color(t::FAINT));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let mut bits = Vec::new();
                        if dis > 0 { bits.push(format!("disable {dis}")); }
                        if en > 0 { bits.push(format!("enable {en}")); }
                        if scope > 0 { bits.push(format!("rescope {scope}")); }
                        let verb = format!("Back up & {}", bits.join(", "));
                        if primary_button(ui, &verb, t::DESTRUCTIVE).clicked() {
                            app.confirm_open = false;
                            open = false;
                            app.start_apply(ctx);
                        }
                        ui.add_space(10.0);
                        if flat_button(ui, "Cancel").clicked() {
                            app.confirm_open = false;
                            open = false;
                        }
                    });
                });
            });
            ui.add_space(14.0);
        });
    if !open {
        app.confirm_open = false;
    }
}

fn change_row(app: &App, ui: &mut egui::Ui, c: &super::PlannedChange) {
    use super::ChangeKind;
    let r = app.rows.iter().find(|r| r.rule.name == c.name);
    let (verb, vc, bg, reason) = match &c.kind {
        ChangeKind::Disable => (
            "DISABLE",
            t::BLOCK,
            t::VERB_DISABLE_BG,
            r.map(|r| disable_reason(r)).unwrap_or_default(),
        ),
        ChangeKind::Enable => (
            "ENABLE",
            t::ENABLE_GREEN,
            t::BACKUP_BG,
            "currently disabled — will begin allowing this traffic".to_string(),
        ),
        ChangeKind::Profiles { arg, removed, .. } => (
            "RESCOPE",
            t::ACCENT,
            t::ACCENT_TINT,
            format!("remove {removed} — rule stays active on {}", arg.replace(',', ", ")),
        ),
    };
    egui::Frame::none()
        .fill(bg)
        .inner_margin(egui::Margin::symmetric(10.0, 8.0))
        .show(ui, |ui| {
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(Vec2::new(64.0, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                    ui.label(egui::RichText::new(verb).font(t::semibold(11.0)).color(vc));
                });
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.label(egui::RichText::new(&c.display).font(t::semibold(12.5)).color(t::INK));
                    ui.label(egui::RichText::new(reason).font(t::sans(11.0)).color(t::TERTIARY));
                });
            });
        });
    ui.add_space(1.0);
}

fn disable_reason(r: &super::RuleRow) -> String {
    let hits = r.total_hits();
    let flag = r.flags.first().map(|f| format!(" · flagged: {}", f.title)).unwrap_or_default();
    let listen = if r.listening.is_empty() { " · not listening" } else { "" };
    format!("{hits} hits in the audit window{listen}{flag}")
}

fn pad20(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.add_space(20.0);
        ui.vertical(|ui| {
            ui.set_max_width(560.0);
            add(ui);
        });
        ui.add_space(20.0);
    });
}
