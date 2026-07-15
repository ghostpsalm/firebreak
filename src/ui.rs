//! Main window. Boots straight to the rule table: a background worker
//! detects audit state and either analyzes (normal run) or offers an
//! "Enable connection auditing" button in the header (first run). Styled
//! light/Segoe to sit alongside classic Windows admin utilities.

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};

use crate::firewall_rules;
use crate::listeners::{self, Listener};
use crate::model::{BaselineFlag, RuleInfo, RuleUsage};
use crate::pipeline::{self, AnalysisResult, UnmatchedRow};

pub struct RuleRow {
    pub rule: RuleInfo,
    pub usage: Option<RuleUsage>,
    pub flags: Vec<BaselineFlag>,
    /// friendly names of apps seen hitting this rule (from event data)
    pub seen_apps: Vec<String>,
    /// processes currently listening on this inbound rule's scope
    pub listening: Vec<String>,
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

impl Default for AuditContext {
    fn default() -> Self {
        AuditContext {
            collection_started: None,
            last_ingest: None,
            events_processed: 0,
            unmatched_events: 0,
            note: String::new(),
        }
    }
}

// ---- worker messages ----

enum WorkerMsg {
    Progress(String),
    /// auditing off: rules + listeners only, header offers the enable button
    NeedsEnable(Box<AnalysisResult>),
    Ready(Box<AnalysisResult>),
    Failed(String),
}

#[derive(PartialEq)]
enum Phase {
    Loading,
    NeedsEnable,
    Enabling,
    Ready,
}

/// Result of a backup+apply run on the apply worker thread.
struct ApplyOutcome {
    status: String,
    disabled: Vec<String>,
    enabled: Vec<String>,
}

enum SortBy {
    Hits,
    Name,
    LastSeen,
}

// Windows-ish palette (light theme)
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0, 120, 215);
const TAG_DOMAIN: egui::Color32 = egui::Color32::from_rgb(0, 90, 190);
const TAG_PRIVATE: egui::Color32 = egui::Color32::from_rgb(20, 130, 60);
const TAG_PUBLIC: egui::Color32 = egui::Color32::from_rgb(200, 85, 0);
const TAG_ANY: egui::Color32 = egui::Color32::from_rgb(110, 110, 110);
const FLAG_COLOR: egui::Color32 = egui::Color32::from_rgb(170, 110, 0);
const WARN_COLOR: egui::Color32 = egui::Color32::from_rgb(175, 90, 0);
const OK_COLOR: egui::Color32 = egui::Color32::from_rgb(20, 120, 60);

pub struct App {
    db_path: Option<PathBuf>,
    phase: Phase,
    rows: Vec<RuleRow>,
    unmatched: Vec<UnmatchedRow>,
    listeners: Vec<Listener>,
    ctx_info: AuditContext,
    worker_rx: Option<Receiver<WorkerMsg>>,
    progress: String,
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
    applying: Option<Receiver<ApplyOutcome>>,
}

impl App {
    fn base(db_path: Option<PathBuf>) -> Self {
        App {
            db_path,
            phase: Phase::Loading,
            rows: Vec::new(),
            unmatched: Vec::new(),
            listeners: Vec::new(),
            ctx_info: AuditContext::default(),
            worker_rx: None,
            progress: "Detecting audit state…".to_string(),
            filter_text: String::new(),
            only_enabled: true, // audits care about enabled rules first
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

    /// Live app: spawns the initial detect-and-analyze worker.
    fn new_live(db_path: PathBuf, egui_ctx: egui::Context) -> Self {
        let mut app = App::base(Some(db_path.clone()));
        let (tx, rx) = std::sync::mpsc::channel();
        app.worker_rx = Some(rx);
        std::thread::spawn(move || {
            let progress = {
                let tx = tx.clone();
                let ctx = egui_ctx.clone();
                move |s: &str| {
                    let _ = tx.send(WorkerMsg::Progress(s.to_string()));
                    ctx.request_repaint();
                }
            };
            let msg = match pipeline::audit_enabled() {
                Ok(true) => match pipeline::analyze(&db_path, &progress) {
                    Ok(r) => WorkerMsg::Ready(Box::new(r)),
                    Err(e) => WorkerMsg::Failed(format!("{e:#}")),
                },
                Ok(false) => match pipeline::rules_only(&progress) {
                    Ok(r) => WorkerMsg::NeedsEnable(Box::new(r)),
                    Err(e) => WorkerMsg::Failed(format!("{e:#}")),
                },
                Err(e) => WorkerMsg::Failed(format!("{e:#}")),
            };
            let _ = tx.send(msg);
            egui_ctx.request_repaint();
        });
        app
    }

    /// Preview app: preloaded data, no workers, no DB.
    fn new_ready(
        rows: Vec<RuleRow>,
        ctx_info: AuditContext,
        unmatched: Vec<UnmatchedRow>,
        listeners: Vec<Listener>,
    ) -> Self {
        let mut app = App::base(None);
        app.phase = Phase::Ready;
        app.rows = rows;
        app.ctx_info = ctx_info;
        app.unmatched = unmatched;
        app.listeners = listeners;
        app.progress = String::new();
        app
    }

    fn start_enable(&mut self, egui_ctx: &egui::Context) {
        let Some(db_path) = self.db_path.clone() else {
            self.status = "Preview mode — enable is disabled.".to_string();
            return;
        };
        self.phase = Phase::Enabling;
        self.progress = "Enabling connection auditing…".to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        self.worker_rx = Some(rx);
        let egui_ctx = egui_ctx.clone();
        std::thread::spawn(move || {
            let progress = {
                let tx = tx.clone();
                let ctx = egui_ctx.clone();
                move |s: &str| {
                    let _ = tx.send(WorkerMsg::Progress(s.to_string()));
                    ctx.request_repaint();
                }
            };
            let msg = match pipeline::enable_collection(&db_path, &progress)
                .and_then(|()| pipeline::analyze(&db_path, &progress))
            {
                Ok(r) => WorkerMsg::Ready(Box::new(r)),
                Err(e) => WorkerMsg::Failed(format!("{e:#}")),
            };
            let _ = tx.send(msg);
            egui_ctx.request_repaint();
        });
    }

    fn poll_worker(&mut self) {
        let Some(rx) = &self.worker_rx else { return };
        loop {
            match rx.try_recv() {
                Ok(WorkerMsg::Progress(s)) => self.progress = s,
                Ok(WorkerMsg::NeedsEnable(result)) => {
                    let r = *result;
                    self.rows = r.rows;
                    self.ctx_info = r.ctx;
                    self.unmatched = r.unmatched;
                    self.listeners = r.listeners;
                    self.phase = Phase::NeedsEnable;
                    self.progress = String::new();
                    self.worker_rx = None;
                    return;
                }
                Ok(WorkerMsg::Ready(result)) => {
                    let r = *result;
                    self.rows = r.rows;
                    self.ctx_info = r.ctx;
                    self.unmatched = r.unmatched;
                    self.listeners = r.listeners;
                    self.phase = Phase::Ready;
                    self.progress = String::new();
                    self.status = format!(
                        "Ingested {} events ({} unattributed).",
                        self.ctx_info.events_processed, self.ctx_info.unmatched_events
                    );
                    self.worker_rx = None;
                    return;
                }
                Ok(WorkerMsg::Failed(e)) => {
                    self.phase = if self.phase == Phase::Enabling {
                        Phase::NeedsEnable
                    } else {
                        Phase::Ready
                    };
                    self.progress = String::new();
                    self.status = format!("Error: {e}");
                    self.worker_rx = None;
                    return;
                }
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.worker_rx = None;
                    return;
                }
            }
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
                    || r.listening
                        .iter()
                        .any(|l| l.to_lowercase().contains(&needle))
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

    fn header_ui(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("firebreak");
            ui.label(egui::RichText::new("Windows Firewall rule-usage audit").weak());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                match self.phase {
                    Phase::NeedsEnable => {
                        let btn = egui::Button::new(
                            egui::RichText::new("  Enable connection auditing  ")
                                .color(egui::Color32::WHITE),
                        )
                        .fill(ACCENT);
                        if ui.add(btn).clicked() {
                            self.start_enable(ctx);
                        }
                    }
                    Phase::Loading | Phase::Enabling => {
                        ui.spinner();
                        ui.label(&self.progress);
                    }
                    Phase::Ready => {}
                }
            });
        });
        ui.horizontal_wrapped(|ui| {
            if let Some(start) = &self.ctx_info.collection_started {
                ui.label(format!("Collecting since: {start}"));
            }
            if let Some(last) = &self.ctx_info.last_ingest {
                ui.label(format!("|  Last ingest: {last}"));
            }
            if self.ctx_info.events_processed > 0 {
                ui.label(format!(
                    "|  Events this run: {} ({} unattributed)",
                    self.ctx_info.events_processed, self.ctx_info.unmatched_events
                ));
            }
        });
        if !self.ctx_info.note.is_empty() {
            ui.colored_label(WARN_COLOR, &self.ctx_info.note);
        }
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(egui::TextEdit::singleline(&mut self.filter_text).desired_width(160.0));
            ui.checkbox(&mut self.only_enabled, "enabled only");
            ui.checkbox(&mut self.only_zero_hit, "zero-hit only");
            ui.checkbox(&mut self.only_flagged, "flagged only");
            ui.separator();
            ui.label("Profiles:");
            ui.checkbox(&mut self.show_domain, "Domain");
            ui.checkbox(&mut self.show_private, "Private");
            ui.checkbox(&mut self.show_public, "Public");
            if !(self.show_domain || self.show_private || self.show_public) {
                ui.colored_label(WARN_COLOR, "(no profiles selected)");
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
        ui.add_space(2.0);
    }

    fn table_ui(&mut self, ui: &mut egui::Ui) {
        let visible = self.visible_indices();
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .column(Column::exact(52.0)) // enabled checkbox
            .column(Column::remainder().at_least(170.0)) // display name
            .column(Column::exact(56.0)) // direction
            .column(Column::exact(46.0)) // action
            .column(Column::initial(105.0).at_least(60.0)) // profile tags
            .column(Column::initial(130.0).at_least(70.0)) // scope
            .column(Column::exact(78.0)) // hits allow/block
            .column(Column::initial(126.0).at_least(80.0)) // last seen
            .column(Column::remainder().at_least(120.0)) // apps seen
            .column(Column::initial(130.0).at_least(80.0)) // listening
            .column(Column::remainder().at_least(100.0)) // flags
            .header(20.0, |mut header| {
                for title in [
                    "Enabled", "Rule", "Dir", "Action", "Profile", "Scope", "Allow/Block",
                    "Last seen", "Apps seen", "Listening", "Flags",
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
                        ui.label(&row.rule.display_name).on_hover_text(format!(
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
                                    "Domain" => TAG_DOMAIN,
                                    "Private" => TAG_PRIVATE,
                                    "Public" => TAG_PUBLIC,
                                    _ => TAG_ANY,
                                };
                                ui.colored_label(color, tag)
                                    .on_hover_text(format!("Raw profile: {}", row.rule.profile));
                            }
                        });
                    });
                    table_row.col(|ui| {
                        let scope = listeners::scope_summary(&row.rule);
                        ui.label(&scope).on_hover_text(scope.clone());
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
                        if row.listening.is_empty() {
                            ui.weak("-");
                        } else {
                            let joined = row.listening.join(", ");
                            ui.colored_label(OK_COLOR, &joined).on_hover_text(joined.clone());
                        }
                    });
                    table_row.col(|ui| {
                        for f in &row.flags {
                            ui.colored_label(FLAG_COLOR, f.title).on_hover_text(f.advice);
                        }
                    });
                });
            });
    }

    fn unmatched_panel(&mut self, ui: &mut egui::Ui) {
        let title = format!("Unattributed events ({})", self.unmatched.len());
        egui::CollapsingHeader::new(title).default_open(true).show(ui, |ui| {
            ui.label(
                "Events that matched WFP filters which are not firewall rules — most commonly \
                 the built-in default block policy (port scans and unsolicited traffic land \
                 here), plus filters from boot sessions firebreak never observed.",
            );
            egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                for u in self.unmatched.iter().take(50) {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(&u.filter_name);
                        ui.label(format!(
                            "(filter {}, boot {})",
                            u.filter_id,
                            u.boot_session.get(..10).unwrap_or(&u.boot_session)
                        ));
                        ui.label(format!(
                            "{} allow / {} block",
                            u.usage.allow_count, u.usage.block_count
                        ));
                        if let Some((app, _)) = u.usage.apps.first() {
                            ui.weak(app);
                        }
                    });
                }
            });
        });
    }

    fn listeners_panel(&mut self, ui: &mut egui::Ui) {
        let title = format!("Active listening sockets ({})", self.listeners.len());
        egui::CollapsingHeader::new(title).show(ui, |ui| {
            let mut sorted: Vec<&Listener> = self.listeners.iter().collect();
            sorted.sort_by_key(|l| (l.proto.clone(), l.local_port));
            egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                for l in sorted {
                    ui.horizontal(|ui| {
                        ui.monospace(format!(
                            "{:<4} {:>21}",
                            l.proto,
                            format!("{}:{}", l.local_address, l.local_port)
                        ));
                        let name = if l.process_name.is_empty() {
                            format!("pid {}", l.pid)
                        } else {
                            format!("{} (pid {})", l.process_name, l.pid)
                        };
                        ui.label(name).on_hover_text(if l.process_path.is_empty() {
                            "(path unavailable)".to_string()
                        } else {
                            l.process_path.clone()
                        });
                    });
                }
            });
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.poll_apply(ctx);

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            self.header_ui(ctx, ui);
        });

        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            let (to_disable, to_enable) = self.pending_changes();
            ui.horizontal(|ui| {
                let pending = to_disable.len() + to_enable.len();
                let btn = ui.add_enabled(
                    pending > 0 && self.applying.is_none() && self.phase == Phase::Ready,
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

        if !self.unmatched.is_empty() || !self.listeners.is_empty() {
            egui::TopBottomPanel::bottom("insight_panels")
                .resizable(true)
                .show(ctx, |ui| {
                    if !self.listeners.is_empty() {
                        self.listeners_panel(ui);
                    }
                    if !self.unmatched.is_empty() {
                        self.unmatched_panel(ui);
                    }
                });
        }

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
                        let apply = egui::Button::new(
                            egui::RichText::new("Backup and apply").color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(180, 40, 40));
                        if ui.add(apply).clicked() {
                            self.confirm_open = false;
                            self.start_apply();
                        }
                    });
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.rows.is_empty() && matches!(self.phase, Phase::Loading | Phase::Enabling) {
                ui.centered_and_justified(|ui| {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(&self.progress);
                    });
                });
            } else {
                self.table_ui(ui);
            }
        });
    }
}

/// Segoe UI + light visuals so the tool sits alongside classic Windows
/// admin utilities. Falls back silently to egui defaults off-Windows.
fn apply_windows_style(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let segoe = std::path::Path::new(&system_root).join(r"Fonts\segoeui.ttf");
    if let Ok(bytes) = std::fs::read(&segoe) {
        fonts
            .font_data
            .insert("segoe".to_string(), egui::FontData::from_owned(bytes));
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            if let Some(list) = fonts.families.get_mut(&family) {
                list.insert(0, "segoe".to_string());
            }
        }
    }
    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::light();
    visuals.panel_fill = egui::Color32::from_rgb(240, 240, 240);
    visuals.window_fill = egui::Color32::from_rgb(240, 240, 240);
    visuals.extreme_bg_color = egui::Color32::WHITE; // text edits, table stripes base
    visuals.faint_bg_color = egui::Color32::from_rgb(246, 246, 246);
    visuals.selection.bg_fill = ACCENT.gamma_multiply(0.35);
    visuals.hyperlink_color = ACCENT;
    for w in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        w.rounding = egui::Rounding::same(2.0);
    }
    ctx.set_visuals(visuals);
}

fn native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1420.0, 800.0])
            .with_min_inner_size([980.0, 520.0]),
        ..Default::default()
    }
}

/// Live run: boots straight to the window; audit detection, enabling, and
/// analysis all happen on background workers.
pub fn run_live(db_path: PathBuf) -> anyhow::Result<()> {
    eframe::run_native(
        "firebreak",
        native_options(),
        Box::new(move |cc| {
            apply_windows_style(&cc.egui_ctx);
            Ok(Box::new(App::new_live(db_path, cc.egui_ctx.clone())))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}

/// Preview run with preloaded mock data (no elevation, no Windows APIs).
pub fn run_preview(
    rows: Vec<RuleRow>,
    ctx_info: AuditContext,
    unmatched: Vec<UnmatchedRow>,
    listeners: Vec<Listener>,
) -> anyhow::Result<()> {
    eframe::run_native(
        "firebreak",
        native_options(),
        Box::new(move |cc| {
            apply_windows_style(&cc.egui_ctx);
            Ok(Box::new(App::new_ready(rows, ctx_info, unmatched, listeners)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}

// Suppress unused warning for Sender re-export pattern in this module.
#[allow(unused)]
fn _assert_send<T: Send>(_: &Sender<T>) {}
