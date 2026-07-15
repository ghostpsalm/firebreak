//! egui table UI: rules ranked by usage, checkboxes for intended
//! enabled-state, confirm-then-commit Apply that backs up the full policy
//! first.

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::sync::mpsc::{Receiver, TryRecvError};

use crate::firewall_rules;
use crate::model::{BaselineFlag, RuleInfo, RuleUsage};

/// Result of a backup+apply run on the worker thread.
struct ApplyOutcome {
    status: String,
    /// names actually applied (used to update row state); empty on failure
    disabled: Vec<String>,
    enabled: Vec<String>,
}

pub struct RuleRow {
    pub rule: RuleInfo,
    pub usage: Option<RuleUsage>,
    pub flags: Vec<BaselineFlag>,
    /// friendly names of apps seen hitting this rule (from event data)
    pub seen_apps: Vec<String>,
    /// what the user wants Enabled to become
    pub target_enabled: bool,
}

impl RuleRow {
    pub fn total_hits(&self) -> i64 {
        self.usage
            .as_ref()
            .map(|u| u.allow_count + u.block_count)
            .unwrap_or(0)
    }
}

pub struct AuditContext {
    pub collection_started: Option<String>,
    pub last_ingest: Option<String>,
    pub events_processed: u64,
    pub unmatched_events: u64,
    pub note: String,
}

enum SortBy {
    Hits,
    Name,
    LastSeen,
}

pub struct App {
    rows: Vec<RuleRow>,
    ctx_info: AuditContext,
    filter_text: String,
    only_enabled: bool,
    only_zero_hit: bool,
    only_flagged: bool,
    show_domain: bool,
    show_private: bool,
    show_public: bool,
    sort: SortBy,
    sort_asc: bool,
    confirm_open: bool,
    status: String,
    /// present while a backup+apply runs on a worker thread — the UI stays
    /// responsive and Apply is disabled until the outcome arrives
    applying: Option<Receiver<ApplyOutcome>>,
}

impl App {
    pub fn new(rows: Vec<RuleRow>, ctx_info: AuditContext) -> Self {
        App {
            rows,
            ctx_info,
            filter_text: String::new(),
            only_enabled: false,
            only_zero_hit: false,
            only_flagged: false,
            show_domain: true,
            show_private: true,
            show_public: true,
            sort: SortBy::Hits,
            sort_asc: true, // zero-hit disable candidates first
            confirm_open: false,
            status: String::new(),
            applying: None,
        }
    }

    fn pending_changes(&self) -> (Vec<String>, Vec<String>) {
        let mut to_disable = Vec::new();
        let mut to_enable = Vec::new();
        for r in &self.rows {
            let currently = r.rule.is_enabled();
            if currently && !r.target_enabled {
                to_disable.push(r.rule.name.clone());
            } else if !currently && r.target_enabled {
                to_enable.push(r.rule.name.clone());
            }
        }
        (to_disable, to_enable)
    }

    /// Kick off backup+apply on a worker thread; PowerShell/netsh take
    /// seconds and must not freeze the frame loop.
    fn start_apply(&mut self) {
        let (to_disable, to_enable) = self.pending_changes();
        let all_rules: Vec<RuleInfo> = self.rows.iter().map(|r| r.rule.clone()).collect();
        let (tx, rx) = std::sync::mpsc::channel();
        self.applying = Some(rx);
        self.status = "Backing up and applying…".to_string();
        std::thread::spawn(move || {
            let backup_msg = match firewall_rules::backup_policy(&all_rules) {
                Ok(path) => format!("Backup written to {}.", path.display()),
                Err(e) => {
                    let _ = tx.send(ApplyOutcome {
                        status: format!("BACKUP FAILED, nothing applied: {e:#}"),
                        disabled: Vec::new(),
                        enabled: Vec::new(),
                    });
                    return;
                }
            };
            let mut errors = Vec::new();
            if let Err(e) = firewall_rules::set_rules_enabled(&to_disable, false) {
                errors.push(format!("disable: {e:#}"));
            }
            if let Err(e) = firewall_rules::set_rules_enabled(&to_enable, true) {
                errors.push(format!("enable: {e:#}"));
            }
            let outcome = if errors.is_empty() {
                ApplyOutcome {
                    status: format!(
                        "{backup_msg} Applied: {} disabled, {} enabled.",
                        to_disable.len(),
                        to_enable.len()
                    ),
                    disabled: to_disable,
                    enabled: to_enable,
                }
            } else {
                // set_rules_enabled reports partial progress in its error;
                // rows are not updated so the UI still shows pre-apply state
                ApplyOutcome {
                    status: format!("{backup_msg} PARTIAL/FAILED apply: {}", errors.join("; ")),
                    disabled: Vec::new(),
                    enabled: Vec::new(),
                }
            };
            let _ = tx.send(outcome);
        });
    }

    fn poll_apply(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.applying {
            match rx.try_recv() {
                Ok(outcome) => {
                    for r in &mut self.rows {
                        if outcome.disabled.contains(&r.rule.name) {
                            r.rule.enabled = "False".to_string();
                        } else if outcome.enabled.contains(&r.rule.name) {
                            r.rule.enabled = "True".to_string();
                        }
                    }
                    self.status = outcome.status;
                    self.applying = None;
                }
                Err(TryRecvError::Empty) => {
                    // keep painting while the worker runs
                    ctx.request_repaint_after(std::time::Duration::from_millis(100));
                }
                Err(TryRecvError::Disconnected) => {
                    self.status = "Apply worker terminated unexpectedly.".to_string();
                    self.applying = None;
                }
            }
        }
    }

    fn visible_indices(&self) -> Vec<usize> {
        let needle = self.filter_text.to_lowercase();
        let mut idx: Vec<usize> = (0..self.rows.len())
            .filter(|&i| {
                let r = &self.rows[i];
                if self.only_enabled && !r.rule.is_enabled() {
                    return false;
                }
                if self.only_zero_hit && r.total_hits() != 0 {
                    return false;
                }
                if self.only_flagged && r.flags.is_empty() {
                    return false;
                }
                if !r
                    .rule
                    .applies_to_profile(self.show_domain, self.show_private, self.show_public)
                {
                    return false;
                }
                if needle.is_empty() {
                    return true;
                }
                r.rule.display_name.to_lowercase().contains(&needle)
                    || r.rule
                        .group
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&needle)
                    || r.rule
                        .program
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&needle)
                    || r.seen_apps
                        .iter()
                        .any(|a| a.to_lowercase().contains(&needle))
            })
            .collect();
        idx.sort_by(|&a, &b| {
            let (ra, rb) = (&self.rows[a], &self.rows[b]);
            let ord = match self.sort {
                SortBy::Hits => ra.total_hits().cmp(&rb.total_hits()),
                SortBy::Name => ra.rule.display_name.cmp(&rb.rule.display_name),
                SortBy::LastSeen => {
                    let la = ra.usage.as_ref().and_then(|u| u.last_seen.clone());
                    let lb = rb.usage.as_ref().and_then(|u| u.last_seen.clone());
                    la.cmp(&lb)
                }
            };
            if self.sort_asc { ord } else { ord.reverse() }
        });
        idx
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_apply(ctx);
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.heading("Windows Firewall Rule-Usage Audit");
            ui.horizontal_wrapped(|ui| {
                if let Some(start) = &self.ctx_info.collection_started {
                    ui.label(format!("Collecting since: {start}"));
                }
                if let Some(last) = &self.ctx_info.last_ingest {
                    ui.label(format!("| Last ingest: {last}"));
                }
                ui.label(format!(
                    "| Events this run: {} ({} unattributed)",
                    self.ctx_info.events_processed, self.ctx_info.unmatched_events
                ));
            });
            if !self.ctx_info.note.is_empty() {
                ui.colored_label(egui::Color32::YELLOW, &self.ctx_info.note);
            }
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut self.filter_text);
                ui.checkbox(&mut self.only_enabled, "enabled only");
                ui.checkbox(&mut self.only_zero_hit, "zero-hit only");
                ui.checkbox(&mut self.only_flagged, "flagged only");
                ui.separator();
                ui.label("Profiles:");
                ui.checkbox(&mut self.show_domain, "Domain");
                ui.checkbox(&mut self.show_private, "Private");
                ui.checkbox(&mut self.show_public, "Public");
                if !(self.show_domain || self.show_private || self.show_public) {
                    ui.colored_label(egui::Color32::YELLOW, "(no profiles selected)");
                }
                ui.separator();
                ui.label("Sort:");
                if ui.selectable_label(matches!(self.sort, SortBy::Hits), "hits").clicked() {
                    self.sort = SortBy::Hits;
                }
                if ui.selectable_label(matches!(self.sort, SortBy::Name), "name").clicked() {
                    self.sort = SortBy::Name;
                }
                if ui
                    .selectable_label(matches!(self.sort, SortBy::LastSeen), "last seen")
                    .clicked()
                {
                    self.sort = SortBy::LastSeen;
                }
                if ui.button(if self.sort_asc { "asc" } else { "desc" }).clicked() {
                    self.sort_asc = !self.sort_asc;
                }
            });
        });

        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            let (to_disable, to_enable) = self.pending_changes();
            ui.horizontal(|ui| {
                let pending = to_disable.len() + to_enable.len();
                let btn = ui.add_enabled(
                    pending > 0 && self.applying.is_none(),
                    egui::Button::new(if self.applying.is_some() {
                        "Applying…".to_string()
                    } else {
                        format!(
                            "Apply changes ({} disable, {} enable)…",
                            to_disable.len(),
                            to_enable.len()
                        )
                    }),
                );
                if btn.clicked() {
                    self.confirm_open = true;
                }
                ui.label(&self.status);
            });
        });

        if self.confirm_open {
            let (to_disable, to_enable) = self.pending_changes();
            egui::Window::new("Confirm changes")
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.label(
                        "A full policy backup (.wfw, restorable with `netsh advfirewall import`) \
                         will be written before anything is changed.",
                    );
                    ui.separator();
                    egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                        if !to_disable.is_empty() {
                            ui.strong(format!("Disable ({}):", to_disable.len()));
                            for name in &to_disable {
                                if let Some(r) = self.rows.iter().find(|r| &r.rule.name == name) {
                                    ui.label(format!("  {} [{}]", r.rule.display_name, name));
                                }
                            }
                        }
                        if !to_enable.is_empty() {
                            ui.strong(format!("Enable ({}):", to_enable.len()));
                            for name in &to_enable {
                                if let Some(r) = self.rows.iter().find(|r| &r.rule.name == name) {
                                    ui.label(format!("  {} [{}]", r.rule.display_name, name));
                                }
                            }
                        }
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.confirm_open = false;
                        }
                        if ui
                            .add(egui::Button::new("Backup and apply").fill(egui::Color32::DARK_RED))
                            .clicked()
                        {
                            self.confirm_open = false;
                            self.start_apply();
                        }
                    });
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            let visible = self.visible_indices();
            TableBuilder::new(ui)
                .striped(true)
                .column(Column::exact(60.0))  // enabled checkbox
                .column(Column::remainder().at_least(200.0)) // display name
                .column(Column::exact(60.0))  // direction
                .column(Column::exact(50.0))  // action
                .column(Column::exact(130.0)) // profile tags
                .column(Column::exact(90.0))  // hits allow/block
                .column(Column::exact(140.0)) // last seen
                .column(Column::remainder().at_least(160.0)) // apps seen
                .column(Column::remainder().at_least(120.0)) // baseline flags
                .header(20.0, |mut header| {
                    for title in [
                        "Enabled", "Rule", "Dir", "Action", "Profile", "Allow/Block",
                        "Last seen", "Apps seen", "Flags",
                    ] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|body| {
                    body.rows(20.0, visible.len(), |mut table_row| {
                        let i = visible[table_row.index()];
                        let row = &mut self.rows[i];
                        table_row.col(|ui| {
                            let changed = row.target_enabled != row.rule.is_enabled();
                            let cb = ui.checkbox(&mut row.target_enabled, "");
                            if changed {
                                cb.highlight();
                            }
                        });
                        table_row.col(|ui| {
                            let description = row
                                .rule
                                .description
                                .as_deref()
                                .filter(|d| !d.trim().is_empty())
                                .unwrap_or("(no description)");
                            ui.label(&row.rule.display_name)
                                .on_hover_text(format!(
                                    "{}\n\n{}\nGroup: {}\nProgram: {}\nPorts: {} local / {} remote ({})",
                                    description,
                                    row.rule.name,
                                    row.rule.group.as_deref().unwrap_or("-"),
                                    row.rule.program.as_deref().unwrap_or("Any"),
                                    row.rule.local_port.as_deref().unwrap_or("Any"),
                                    row.rule.remote_port.as_deref().unwrap_or("Any"),
                                    row.rule.protocol.as_deref().unwrap_or("Any"),
                                ));
                        });
                        table_row.col(|ui| {
                            ui.label(&row.rule.direction);
                        });
                        table_row.col(|ui| {
                            ui.label(&row.rule.action);
                        });
                        table_row.col(|ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 3.0;
                                for tag in row.rule.profile_tags() {
                                    let color = match tag {
                                        "Domain" => egui::Color32::from_rgb(90, 140, 220),
                                        "Private" => egui::Color32::from_rgb(90, 180, 110),
                                        "Public" => egui::Color32::from_rgb(220, 140, 60),
                                        _ => egui::Color32::GRAY, // Any / unparsed
                                    };
                                    ui.colored_label(color, tag)
                                        .on_hover_text(format!("Raw profile: {}", row.rule.profile));
                                }
                            });
                        });
                        table_row.col(|ui| {
                            match &row.usage {
                                Some(u) => ui.label(format!("{}/{}", u.allow_count, u.block_count)),
                                None => ui.weak("0/0"),
                            };
                        });
                        table_row.col(|ui| {
                            let last = row
                                .usage
                                .as_ref()
                                .and_then(|u| u.last_seen.as_deref())
                                .unwrap_or("never");
                            ui.label(last);
                        });
                        table_row.col(|ui| {
                            if row.seen_apps.is_empty() {
                                ui.weak("-");
                            } else {
                                let joined = row.seen_apps.join(", ");
                                ui.label(&joined).on_hover_text(joined.clone());
                            }
                        });
                        table_row.col(|ui| {
                            for f in &row.flags {
                                ui.colored_label(egui::Color32::from_rgb(230, 160, 30), f.title)
                                    .on_hover_text(f.advice);
                            }
                        });
                    });
                });
        });
    }
}

pub fn run(rows: Vec<RuleRow>, ctx_info: AuditContext) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 760.0]),
        ..Default::default()
    };
    eframe::run_native(
        "firebreak",
        options,
        Box::new(move |_cc| Ok(Box::new(App::new(rows, ctx_info)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}
