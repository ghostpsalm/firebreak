//! Main window, rebuilt to the "Firebreak UI Concept" design handoff.
//! Fixed bands top-to-bottom: title bar, evidence header, (conditional)
//! warning band, filter bar, rule table (+ optional detail panel), evidence
//! drawer, (conditional) pending-changes footer. Custom row painting keeps
//! the table grid, checkbox intent states, chips, and accent edge bars exact.

use eframe::egui::{self, Align2, Color32, Rect, Stroke, Vec2};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};

use crate::listeners::Listener;
use crate::model::{BaselineFlag, RuleInfo, RuleUsage};
use crate::pipeline::{self, AnalysisResult, UnmatchedRow};
use crate::theme::{self as t};
use crate::{firewall_rules, time_util};

const ROW_H: f32 = 31.0;
const HEADER_H: f32 = 28.0;
const PAGE_PAD: f32 = 14.0;

pub struct RuleRow {
    pub rule: RuleInfo,
    pub usage: Option<RuleUsage>,
    pub flags: Vec<BaselineFlag>,
    pub seen_apps: Vec<String>,
    pub listening: Vec<String>,
    pub target_enabled: bool,
}

impl RuleRow {
    pub fn total_hits(&self) -> i64 {
        self.usage.as_ref().map(|u| u.allow_count + u.block_count).unwrap_or(0)
    }
    fn is_zero_hit(&self) -> bool {
        self.total_hits() == 0
    }
    fn pending(&self) -> bool {
        self.target_enabled != self.rule.is_enabled()
    }
}

pub struct AuditContext {
    pub hostname: String,
    pub auditing_active: bool,
    pub collection_started: Option<String>,
    pub last_ingest: Option<String>,
    pub events_processed: u64,
    pub unmatched_events: u64,
    pub note: String,
}

impl Default for AuditContext {
    fn default() -> Self {
        AuditContext {
            hostname: String::new(),
            auditing_active: false,
            collection_started: None,
            last_ingest: None,
            events_processed: 0,
            unmatched_events: 0,
            note: String::new(),
        }
    }
}

// ---- workers ----

enum WorkerMsg {
    /// audit state resolved — lets the header show it before the slower
    /// rule enumeration finishes
    AuditState(bool),
    Progress(String),
    /// preliminary result from cached rules, shown instantly; a fresh
    /// Ready follows once the live enumeration completes
    Preliminary(Box<AnalysisResult>),
    NeedsEnable(Box<AnalysisResult>),
    Ready(Box<AnalysisResult>),
    Failed(String),
}

/// Streamed apply progress — one message per step so the footer shows
/// "2 of 3" and rows show per-rule status/failures.
enum ApplyMsg {
    BackupOk(String),
    BackupFailed(String),
    RuleStart { name: String },
    RuleDone { name: String, target_enabled: bool, error: Option<String> },
    Finished,
}

#[derive(PartialEq, Clone, Copy)]
enum Phase {
    Loading,
    NeedsEnable,
    Enabling,
    Ready,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Sockets,
    Unattributed,
}

#[derive(PartialEq, Clone, Copy)]
enum Sort {
    Hits,
    Name,
    LastSeen,
}

#[derive(PartialEq, Clone, Copy)]
pub(crate) enum DirFilter {
    In,
    Out,
    All,
}

struct ApplyState {
    rx: Receiver<ApplyMsg>,
    total: usize,
    done: usize,
    current: Option<String>,
    backup: Option<String>,
    backup_failed: Option<String>,
    /// per-rule outcome: name -> Ok(target) | Err(msg)
    results: std::collections::HashMap<String, Result<bool, String>>,
    finished: bool,
    stop_requested: bool,
}

pub struct App {
    db_path: Option<PathBuf>,
    phase: Phase,
    rows: Vec<RuleRow>,
    unmatched: Vec<UnmatchedRow>,
    listeners: Vec<Listener>,
    ctx_info: AuditContext,
    worker_rx: Option<Receiver<WorkerMsg>>,
    progress: String,

    // filters
    filter_text: String,
    dir_filter: DirFilter,
    only_enabled: bool,
    only_zero_hit: bool,
    only_flagged: bool,
    show_domain: bool,
    show_private: bool,
    show_public: bool,
    sort: Sort,
    sort_asc: bool,

    selected: Option<usize>,
    drawer_open: bool,
    tab: Tab,
    audit_checked: bool,

    confirm_open: bool,
    apply: Option<ApplyState>,
    status: String,
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
            progress: "Detecting audit state…".into(),
            filter_text: String::new(),
            dir_filter: DirFilter::In, // audits start with inbound exposure
            only_enabled: true,
            only_zero_hit: false,
            only_flagged: false,
            show_domain: true,
            show_private: true,
            show_public: true,
            sort: Sort::Hits,
            sort_asc: false, // hits descending by default (design)
            selected: None,
            drawer_open: false,
            tab: Tab::Sockets,
            audit_checked: false,
            confirm_open: false,
            apply: None,
            status: String::new(),
        }
    }

    fn new_live(db_path: PathBuf, egui_ctx: egui::Context) -> Self {
        let mut app = App::base(Some(db_path.clone()));
        app.spawn_detect(db_path, egui_ctx);
        app
    }

    fn spawn_detect(&mut self, db_path: PathBuf, egui_ctx: egui::Context) {
        self.audit_checked = false;
        let (tx, rx) = std::sync::mpsc::channel();
        self.worker_rx = Some(rx);
        std::thread::spawn(move || {
            let progress = {
                let tx = tx.clone();
                let ctx = egui_ctx.clone();
                move |s: &str| {
                    let _ = tx.send(WorkerMsg::Progress(s.to_string()));
                    ctx.request_repaint();
                }
            };
            // audit state first — cheap, and lets the header settle before
            // the slower rule enumeration
            progress("Checking Windows audit policy…");
            let enabled = match pipeline::audit_enabled() {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx.send(WorkerMsg::Failed(format!("{e:#}")));
                    egui_ctx.request_repaint();
                    return;
                }
            };
            let _ = tx.send(WorkerMsg::AuditState(enabled));
            egui_ctx.request_repaint();

            if enabled {
                // instant paint from cached rules while the live query runs
                if let Some(prelim) = pipeline::quick_cached_result(&db_path) {
                    let _ = tx.send(WorkerMsg::Preliminary(Box::new(prelim)));
                    egui_ctx.request_repaint();
                }
                let msg = match pipeline::analyze(&db_path, &progress) {
                    Ok(r) => WorkerMsg::Ready(Box::new(r)),
                    Err(e) => WorkerMsg::Failed(format!("{e:#}")),
                };
                let _ = tx.send(msg);
            } else {
                let msg = match pipeline::rules_only(&progress) {
                    Ok(r) => WorkerMsg::NeedsEnable(Box::new(r)),
                    Err(e) => WorkerMsg::Failed(format!("{e:#}")),
                };
                let _ = tx.send(msg);
            }
            egui_ctx.request_repaint();
        });
    }

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
        app.drawer_open = true;
        app.audit_checked = true;
        app.progress.clear();
        // preview-only state overrides for screenshotting non-default screens
        match std::env::var("FIREBREAK_PREVIEW_STATE").as_deref() {
            Ok("firstrun") => {
                app.phase = Phase::NeedsEnable;
                app.ctx_info.auditing_active = false;
                for r in &mut app.rows {
                    r.usage = None;
                    r.target_enabled = r.rule.is_enabled();
                }
            }
            Ok("modal") => app.confirm_open = true,
            Ok("selected") => app.selected = Some(0),
            _ => {}
        }
        app
    }

    fn start_enable(&mut self, egui_ctx: &egui::Context) {
        let Some(db_path) = self.db_path.clone() else {
            self.status = "Preview mode — enable is disabled.".into();
            return;
        };
        self.phase = Phase::Enabling;
        self.progress = "Enabling connection auditing…".into();
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
        // drain into a local buffer so message handlers can take &mut self
        let mut msgs = Vec::new();
        if let Some(rx) = &self.worker_rx {
            loop {
                match rx.try_recv() {
                    Ok(m) => msgs.push(m),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.worker_rx = None;
                        break;
                    }
                }
            }
        }
        for m in msgs {
            match m {
                WorkerMsg::AuditState(b) => {
                    self.ctx_info.auditing_active = b;
                    self.audit_checked = true;
                }
                WorkerMsg::Progress(s) => self.progress = s,
                WorkerMsg::Preliminary(r) => {
                    // show cached rules immediately; phase stays Loading so
                    // the header still signals a refresh is in flight
                    self.absorb(*r);
                    if !self.rows.is_empty() {
                        self.drawer_open = true;
                    }
                }
                WorkerMsg::NeedsEnable(r) => {
                    self.absorb(*r);
                    self.phase = Phase::NeedsEnable;
                    self.worker_rx = None;
                }
                WorkerMsg::Ready(r) => {
                    let ev = r.ctx.events_processed;
                    let un = r.ctx.unmatched_events;
                    self.absorb(*r);
                    self.phase = Phase::Ready;
                    self.drawer_open = self.drawer_open || !self.rows.is_empty();
                    self.status = format!("Ingested {ev} events ({un} unattributed).");
                    self.worker_rx = None;
                }
                WorkerMsg::Failed(e) => {
                    self.phase = if self.phase == Phase::Enabling {
                        Phase::NeedsEnable
                    } else {
                        Phase::Ready
                    };
                    self.status = format!("Error: {e}");
                    self.worker_rx = None;
                }
            }
        }
    }

    fn absorb(&mut self, r: AnalysisResult) {
        self.rows = r.rows;
        self.ctx_info = r.ctx;
        self.unmatched = r.unmatched;
        self.listeners = r.listeners;
        self.progress.clear();
        self.selected = None;
    }

    // ---- pending / apply ----

    fn pending(&self) -> (Vec<String>, Vec<String>) {
        let mut dis = Vec::new();
        let mut en = Vec::new();
        for r in &self.rows {
            if r.rule.is_enabled() && !r.target_enabled {
                dis.push(r.rule.name.clone());
            } else if !r.rule.is_enabled() && r.target_enabled {
                en.push(r.rule.name.clone());
            }
        }
        (dis, en)
    }

    /// Coverage/evidence-age assessment → warning band. Some(hours) when
    /// evidence is younger than the meaningful window.
    fn young_evidence_hours(&self) -> Option<f64> {
        if !self.ctx_info.auditing_active {
            return None;
        }
        let started = self.ctx_info.collection_started.as_deref()?;
        let hours = time_util::hours_since(started)?;
        if hours < 24.0 * 7.0 {
            Some(hours)
        } else {
            None
        }
    }

    fn revert_all(&mut self) {
        for r in &mut self.rows {
            r.target_enabled = r.rule.is_enabled();
        }
    }

    fn start_apply(&mut self, egui_ctx: &egui::Context) {
        let (dis, en) = self.pending();
        let total = dis.len() + en.len();
        if total == 0 {
            return;
        }
        let all_rules: Vec<RuleInfo> = self.rows.iter().map(|r| r.rule.clone()).collect();
        let (tx, rx) = std::sync::mpsc::channel();
        self.apply = Some(ApplyState {
            rx,
            total,
            done: 0,
            current: None,
            backup: None,
            backup_failed: None,
            results: std::collections::HashMap::new(),
            finished: false,
            stop_requested: false,
        });
        let egui_ctx = egui_ctx.clone();
        std::thread::spawn(move || {
            match firewall_rules::backup_policy(&all_rules) {
                Ok(path) => {
                    let _ = tx.send(ApplyMsg::BackupOk(path.display().to_string()));
                }
                Err(e) => {
                    let _ = tx.send(ApplyMsg::BackupFailed(format!("{e:#}")));
                    let _ = tx.send(ApplyMsg::Finished);
                    egui_ctx.request_repaint();
                    return;
                }
            }
            // disables first (design lists disables above enables)
            for (name, target) in dis
                .into_iter()
                .map(|n| (n, false))
                .chain(en.into_iter().map(|n| (n, true)))
            {
                let _ = tx.send(ApplyMsg::RuleStart { name: name.clone() });
                egui_ctx.request_repaint();
                let error = firewall_rules::set_rule_enabled(&name, target)
                    .err()
                    .map(|e| format!("{e:#}"));
                let _ = tx.send(ApplyMsg::RuleDone {
                    name,
                    target_enabled: target,
                    error,
                });
                egui_ctx.request_repaint();
            }
            let _ = tx.send(ApplyMsg::Finished);
            egui_ctx.request_repaint();
        });
    }

    fn poll_apply(&mut self, ctx: &egui::Context) {
        let Some(apply) = &mut self.apply else { return };
        let mut newly_committed: Vec<(String, bool)> = Vec::new();
        loop {
            match apply.rx.try_recv() {
                Ok(ApplyMsg::BackupOk(p)) => apply.backup = Some(p),
                Ok(ApplyMsg::BackupFailed(e)) => apply.backup_failed = Some(e),
                Ok(ApplyMsg::RuleStart { name }) => apply.current = Some(name),
                Ok(ApplyMsg::RuleDone { name, target_enabled, error }) => {
                    apply.done += 1;
                    apply.current = None;
                    match error {
                        None => {
                            apply.results.insert(name.clone(), Ok(target_enabled));
                            newly_committed.push((name, target_enabled));
                        }
                        Some(e) => {
                            apply.results.insert(name, Err(e));
                        }
                    }
                }
                Ok(ApplyMsg::Finished) => apply.finished = true,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    apply.finished = true;
                    break;
                }
            }
        }
        // commit saved state for succeeded rules so their checkboxes settle
        for (name, target) in newly_committed {
            if let Some(r) = self.rows.iter_mut().find(|r| r.rule.name == name) {
                r.rule.enabled = if target { "True" } else { "False" }.into();
                r.target_enabled = target;
            }
        }
        if !apply.finished {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        } else {
            // keep the ApplyState around if any failures remain (partial-
            // failure footer); otherwise clear back to normal
            let any_fail = apply.results.values().any(|r| r.is_err());
            let backup_failed = apply.backup_failed.is_some();
            if !any_fail && !backup_failed {
                let n = apply.done;
                self.apply = None;
                self.status = format!("Applied {n} change(s).");
            }
        }
    }

    fn apply_running(&self) -> bool {
        self.apply.as_ref().map_or(false, |a| !a.finished)
    }
    fn apply_partial_failure(&self) -> bool {
        self.apply.as_ref().map_or(false, |a| {
            a.finished && (a.results.values().any(|r| r.is_err()) || a.backup_failed.is_some())
        })
    }

    // ---- filtering ----

    fn visible(&self) -> Vec<usize> {
        let needle = self.filter_text.to_lowercase();
        let mut idx: Vec<usize> = (0..self.rows.len())
            .filter(|&i| {
                let r = &self.rows[i];
                match self.dir_filter {
                    DirFilter::In if !r.rule.direction.eq_ignore_ascii_case("inbound") => return false,
                    DirFilter::Out if !r.rule.direction.eq_ignore_ascii_case("outbound") => return false,
                    _ => {}
                }
                if self.only_enabled && !r.rule.is_enabled() {
                    return false;
                }
                if self.only_zero_hit && (!r.is_zero_hit() || !self.ctx_info.auditing_active) {
                    return false;
                }
                if self.only_flagged && r.flags.is_empty() {
                    return false;
                }
                if !r.rule.applies_to_profile(self.show_domain, self.show_private, self.show_public) {
                    return false;
                }
                if needle.is_empty() {
                    return true;
                }
                r.rule.display_name.to_lowercase().contains(&needle)
                    || r.rule.group.as_deref().unwrap_or("").to_lowercase().contains(&needle)
                    || r.rule.program.as_deref().unwrap_or("").to_lowercase().contains(&needle)
                    || r.seen_apps.iter().any(|a| a.to_lowercase().contains(&needle))
                    || r.listening.iter().any(|l| l.to_lowercase().contains(&needle))
            })
            .collect();
        idx.sort_by(|&a, &b| {
            let (ra, rb) = (&self.rows[a], &self.rows[b]);
            let ord = match self.sort {
                Sort::Hits => ra.total_hits().cmp(&rb.total_hits()),
                Sort::Name => ra.rule.display_name.cmp(&rb.rule.display_name),
                Sort::LastSeen => {
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

// ─────────────────────────────────────────────────────────────────────────
// rendering
// ─────────────────────────────────────────────────────────────────────────

mod paint;

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.poll_apply(ctx);
        paint::window(self, ctx);
    }
}

// ---- entry points ----

fn native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1460.0, 900.0])
            .with_min_inner_size([1000.0, 620.0])
            .with_decorations(false) // custom title bar (see paint::titlebar)
            .with_resizable(true)
            .with_title("firebreak"),
        ..Default::default()
    }
}

pub fn run_live(db_path: PathBuf) -> anyhow::Result<()> {
    eframe::run_native(
        "firebreak",
        native_options(),
        Box::new(move |cc| {
            t::apply_style(&cc.egui_ctx);
            Ok(Box::new(App::new_live(db_path, cc.egui_ctx.clone())))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}

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
            t::apply_style(&cc.egui_ctx);
            Ok(Box::new(App::new_ready(rows, ctx_info, unmatched, listeners)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))
}

// small helpers shared with the paint module
pub(crate) fn profile_chip(tag: &str) -> (&'static str, Color32, Color32, Color32) {
    match tag {
        "Domain" => t::CHIP_DOM,
        "Private" => t::CHIP_PRV,
        "Public" => t::CHIP_PUB,
        _ => t::CHIP_ANY,
    }
}

pub(crate) use helpers::*;
mod helpers {
    use super::*;

    /// Draw text clipped to a cell, left-aligned, vertically centered.
    pub fn cell_text(
        painter: &egui::Painter,
        rect: Rect,
        text: &str,
        font: egui::FontId,
        color: Color32,
        left_pad: f32,
    ) {
        let clip = painter.with_clip_rect(rect);
        clip.text(
            egui::pos2(rect.left() + left_pad, rect.center().y),
            Align2::LEFT_CENTER,
            text,
            font,
            color,
        );
    }

    pub fn stroke_bottom(painter: &egui::Painter, rect: Rect, color: Color32) {
        painter.hline(rect.x_range(), rect.bottom() - 0.5, Stroke::new(1.0, color));
    }

    /// Outlined profile chip; returns width consumed.
    pub fn chip(painter: &egui::Painter, top_left: egui::Pos2, tag: &str) -> f32 {
        let (label, fg, bg, border) = profile_chip(tag);
        let font = t::semibold(9.5);
        let galley = painter.layout_no_wrap(label.to_string(), font.clone(), fg);
        let w = galley.size().x + 10.0;
        let h = 15.0;
        let r = Rect::from_min_size(top_left, Vec2::new(w, h));
        painter.rect(r, 0.0, bg, Stroke::new(1.0, border));
        painter.galley(egui::pos2(r.left() + 5.0, r.center().y - galley.size().y / 2.0), galley, fg);
        w + 3.0
    }
}
