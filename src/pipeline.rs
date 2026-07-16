//! The analysis pipeline, callable from the UI worker thread or the
//! console (--no-ui / --enable-only) paths. Opens its own Store — SQLite
//! connections are cheap and this keeps the UI thread free of DB state.

use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::BTreeSet;
use std::path::Path;

use crate::listeners::{self, Listener};
use crate::model::RuleUsage;
use crate::store::Store;
use crate::{app_identity, audit_control, baseline_checks, event_query, firewall_rules, ui};

pub fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "this host".to_string())
}

/// Group key for a rule's DisplayName + direction, shared by profile
/// variants of the same rule. Used both when attributing a FilterOrigin
/// that is a DisplayName and when looking a rule's usage back up.
fn disp_key(display_name: &str, direction: &str) -> String {
    let dir = if direction.eq_ignore_ascii_case("inbound") {
        "in"
    } else if direction.eq_ignore_ascii_case("outbound") {
        "out"
    } else {
        "?"
    };
    format!("disp:{}|{}", display_name.to_lowercase(), dir)
}

/// Friendlier label for a default/system-filter FilterOrigin.
fn describe_origin(origin: &str) -> String {
    let lc = origin.to_lowercase();
    if lc == "unknown" || lc.is_empty() {
        "Unknown — decided by a default/system filter, not a firewall rule".into()
    } else if lc.contains("default outbound") {
        "Default outbound policy (allow) — no specific rule".into()
    } else if lc.contains("default inbound") {
        "Default inbound policy (block) — no specific rule".into()
    } else if lc.contains("boot") {
        format!("{origin} — boot-time default filter")
    } else if lc.contains("stealth") {
        format!("{origin} — stealth-mode default filter")
    } else if lc.contains("appcontainer") || lc.contains("loopback") || lc.contains("quarantine") {
        format!("{origin} — system filter (not a firewall rule)")
    } else {
        format!("{origin} — default/system filter")
    }
}

/// One unattributed bucket, explained: which WFP filter the events matched
/// (by recorded name when we have it), in which boot session.
pub struct UnmatchedRow {
    pub filter_id: String,
    pub boot_session: String,
    pub filter_name: String,
    pub usage: RuleUsage,
}

pub struct AnalysisResult {
    pub rows: Vec<ui::RuleRow>,
    pub ctx: ui::AuditContext,
    pub unmatched: Vec<UnmatchedRow>,
    pub listeners: Vec<Listener>,
}

/// Is Filtering Platform Connection auditing fully on?
pub fn audit_enabled() -> Result<bool> {
    Ok(audit_control::query_audit_state()?.fully_enabled())
}

/// Clear aggregated usage + checkpoint so the next run re-scans the whole
/// Security log. Manual counterpart to the automatic model-change reset.
pub fn reset(db_path: &Path) -> Result<()> {
    Store::open(db_path)?.reset_ingestion()
}

/// First-run path: record prior audit config, enable auditing, size the
/// log, snapshot rules, and start the checkpoint cursor. Idempotent.
pub fn enable_collection(db_path: &Path, progress: &dyn Fn(&str)) -> Result<()> {
    let store = Store::open(db_path)?;
    let audit_state = audit_control::query_audit_state()?;
    if !audit_state.fully_enabled() {
        // record what we're about to change, once, so --restore-audit can
        // put the host back exactly as found
        if store.get_meta("prior_audit_success")?.is_none() {
            store.set_meta("prior_audit_success", &audit_state.success.to_string())?;
            store.set_meta("prior_audit_failure", &audit_state.failure.to_string())?;
        }
        progress("Enabling Filtering Platform Connection auditing…");
        audit_control::enable_auditing()?;
    }
    match audit_control::security_log_max_bytes() {
        Ok(current) => {
            if current < audit_control::DEFAULT_SECURITY_LOG_BYTES {
                if store.get_meta("prior_log_max_bytes")?.is_none() {
                    store.set_meta("prior_log_max_bytes", &current.to_string())?;
                }
                progress("Raising Security log size…");
                if let Err(e) = audit_control::set_security_log_max_bytes(
                    audit_control::DEFAULT_SECURITY_LOG_BYTES,
                ) {
                    eprintln!("warning: could not resize Security log: {e:#}");
                }
            }
        }
        Err(e) => eprintln!("warning: could not read Security log size: {e:#}"),
    }
    let now = now_iso();
    if store.get_meta("collection_started")?.is_none() {
        store.set_meta("collection_started", &now)?;
    }
    if store.checkpoint_record_id()?.is_none() {
        // start the cursor at the newest existing record so pre-enable
        // history (from any earlier auditing period) isn't swept in; the
        // adoption path in analyze() handles auditing that predates us
        let start = event_query::newest_record_id()?.unwrap_or(0);
        store.set_checkpoint_record_id(start)?;
    }
    progress("Snapshotting rule set…");
    match firewall_rules::enumerate_rules() {
        Ok(rules) => store.snapshot_rules(&rules, &now)?,
        Err(e) => eprintln!("warning: rule snapshot failed: {e:#}"),
    }
    Ok(())
}

/// Build the report rows from rules + aggregated usage + current listeners.
/// Usage is looked up by exact InstanceID, else by the DisplayName+direction
/// group key (profile variants share it).
fn build_rows(
    rules: Vec<crate::model::RuleInfo>,
    all_usage: &std::collections::HashMap<String, RuleUsage>,
    listener_list: &[Listener],
) -> Vec<ui::RuleRow> {
    rules
        .into_iter()
        .map(|rule| {
            let usage = all_usage
                .get(&rule.name)
                .or_else(|| all_usage.get(&disp_key(&rule.display_name, &rule.direction)))
                .cloned();
            let flags = baseline_checks::flags_for(&rule);
            let seen_apps: Vec<String> = usage
                .as_ref()
                .map(|u| {
                    let mut names = BTreeSet::new();
                    for (path, _hits) in u.apps.iter().take(8) {
                        let ident = app_identity::identify(path);
                        if ident.company.is_empty() {
                            names.insert(ident.friendly_name);
                        } else {
                            names.insert(format!("{} ({})", ident.friendly_name, ident.company));
                        }
                    }
                    names.into_iter().collect()
                })
                .unwrap_or_default();
            let listening = listeners::listeners_for_rule(&rule, listener_list);
            let target_enabled = rule.is_enabled();
            ui::RuleRow { rule, usage, flags, seen_apps, listening, target_enabled }
        })
        .collect()
}

/// Default/system-filter buckets ("default:<origin>") as report rows.
fn build_unmatched(store: &Store) -> Result<Vec<UnmatchedRow>> {
    let labels = store.bucket_labels().unwrap_or_default();
    Ok(store
        .unmatched_usage()?
        .into_iter()
        .map(|usage| {
            let origin = usage.rule_id.strip_prefix("default:").unwrap_or(&usage.rule_id);
            let label = labels.get(&usage.rule_id).cloned().unwrap_or_else(|| origin.to_string());
            UnmatchedRow {
                filter_id: String::new(),
                boot_session: String::new(),
                filter_name: describe_origin(&label),
                usage,
            }
        })
        .collect())
}

/// Instant startup: build a result from the cached rule set + whatever the
/// store already holds, without the (slow) live rule enumeration. Returns
/// None if there's no cache yet. A full analyze() refresh follows.
pub fn quick_cached_result(db_path: &Path) -> Option<AnalysisResult> {
    let rules = firewall_rules::load_rules_cache()?;
    let store = Store::open(db_path).ok()?;
    let all_usage = store.all_usage().ok()?;
    let listener_list = listeners::enumerate_listeners().unwrap_or_default();
    let rows = build_rows(rules, &all_usage, &listener_list);
    let unmatched = build_unmatched(&store).unwrap_or_default();
    Some(AnalysisResult {
        rows,
        ctx: ui::AuditContext {
            hostname: hostname(),
            auditing_active: true,
            collection_started: store.get_meta("collection_started").ok().flatten(),
            last_ingest: store.get_meta("last_ingest").ok().flatten(),
            events_processed: 0,
            unmatched_events: 0,
            note: "Showing cached rules — refreshing from Windows…".into(),
        },
        unmatched,
        listeners: listener_list,
    })
}

/// The rule table without any usage data — for the first-run screen before
/// auditing is enabled (rules + scope + current listeners are still useful).
pub fn rules_only(progress: &dyn Fn(&str)) -> Result<AnalysisResult> {
    progress("Enumerating firewall rules…");
    let rules = firewall_rules::enumerate_rules().context("enumerating firewall rules")?;
    firewall_rules::save_rules_cache(&rules);
    progress("Enumerating listening sockets…");
    let listeners = listeners::enumerate_listeners().unwrap_or_default();
    let empty = std::collections::HashMap::new();
    let rows = build_rows(rules, &empty, &listeners);
    Ok(AnalysisResult {
        rows,
        ctx: ui::AuditContext {
            hostname: hostname(),
            auditing_active: false,
            collection_started: None,
            last_ingest: None,
            events_processed: 0,
            unmatched_events: 0,
            note: String::new(),
        },
        unmatched: Vec::new(),
        listeners,
    })
}

/// Full run: ingest new events since the checkpoint, aggregate, and build
/// the report rows. Auditing must already be enabled.
pub fn analyze(db_path: &Path, progress: &dyn Fn(&str)) -> Result<AnalysisResult> {
    let store = Store::open(db_path)?;
    let mut note = String::new();

    if store.checkpoint_record_id()?.is_none() {
        // no checkpoint (first run, or an auto-reset after a model change):
        // adopt whatever history the log still holds, but don't clobber an
        // existing collection-start time
        if store.get_meta("collection_started")?.is_none() {
            store.set_meta(
                "collection_started",
                &event_query::first_event_time()?.unwrap_or_else(now_iso),
            )?;
        }
    }

    let checkpoint = store.checkpoint_record_id()?;
    progress("Loading firewall rules…");
    let rules = firewall_rules::enumerate_rules().context("enumerating firewall rules")?;
    firewall_rules::save_rules_cache(&rules);
    let now = now_iso();
    store.snapshot_rules(&rules, &now)?;

    // coverage-gap check: if the channel's oldest surviving record is past
    // our checkpoint, records in between are gone (log rollover / cleared
    // log). Worded as a gap, not asserted as rollover — an auditing-off
    // period looks identical from here.
    if let (Some(cp), Ok(Some(oldest))) = (checkpoint, event_query::oldest_record_id()) {
        if oldest > cp + 1 {
            note = format!(
                "Possible coverage gap: the Security log's oldest surviving record ({oldest}) \
                 is past the last checkpoint ({cp}) — log rollover, a cleared log, or a period \
                 with auditing disabled. Consider a larger log or more frequent runs. {note}"
            );
        }
    }

    // Attribution model (established from the on-device support export):
    // Windows' FilterOrigin names the *decisive* filter, which for allowed
    // traffic is frequently a system default (mDNS/UDP-5353 and ICMP pings
    // arrive with FilterOrigin "Unknown"), not the user's rule. So we
    // attribute by *scope*: credit every rule whose direction + protocol +
    // local/remote port + program the connection satisfies. One connection
    // can credit several overlapping rules — correct for "is this rule
    // exercised". FilterOrigin is used only to label events that match no
    // rule scope (pure default/system traffic) in the Unattributed panel.
    let scope_index = crate::scope::ScopeIndex::build(&rules);
    let iface_profiles = firewall_rules::interface_profile_map();

    // everything from here to the checkpoint advance is one transaction:
    // a crash rolls back cleanly and a rerun re-ingests without double-count
    store.begin()?;

    progress("Ingesting Security log events…");
    let device_map = app_identity::device_path_map();
    let mut events_processed: u64 = 0;
    let mut unmatched_events: u64 = 0;
    let mut max_record_id: Option<u64> = None;
    let mut errors: u64 = 0;
    // human labels for the default/system buckets, keyed by their rule_id
    let mut bucket_labels: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    let ingest = event_query::query_events(checkpoint, |ev| {
        events_processed += 1;
        if max_record_id.map_or(true, |m| ev.record_id > m) {
            max_record_id = Some(ev.record_id);
        }
        let app = app_identity::normalize_path(&ev.application, &device_map);
        let conn = crate::scope::Conn::from_event(&ev, &app, &iface_profiles);
        let profile = conn.profile.label();
        let matched = scope_index.matching_rules(&conn);
        if matched.is_empty() {
            // no rule's scope covers this connection — a default/system
            // filter allowed/blocked it. Bucket by FilterOrigin.
            unmatched_events += 1;
            let origin = ev.filter_origin.as_deref().unwrap_or("Unknown").trim();
            let origin = if origin.is_empty() { "Unknown" } else { origin };
            let bucket = format!("default:{origin}");
            bucket_labels.entry(bucket.clone()).or_insert_with(|| origin.to_string());
            if store.record_event(&bucket, &ev, &app, profile).is_err() {
                errors += 1;
            }
        } else {
            // credit every rule whose scope this connection matches
            for rule_name in matched {
                if store.record_event(rule_name, &ev, &app, profile).is_err() {
                    errors += 1;
                }
            }
        }
    });
    if let Err(e) = ingest {
        let _ = store.rollback();
        return Err(e).context("querying Security log");
    }
    if errors > 0 {
        eprintln!("warning: {errors} events failed to record");
    }

    // advance the cursor to the newest record processed; the query resumes
    // strictly after it, so nothing is re-read or skipped
    if let Some(id) = max_record_id {
        store.set_checkpoint_record_id(id)?;
    } else if checkpoint.is_none() {
        // no matching events at all: anchor at the channel tail so a later
        // run doesn't rescan the whole log
        let start = event_query::newest_record_id()?.unwrap_or(0);
        store.set_checkpoint_record_id(start)?;
    }
    store.set_meta("last_ingest", &now)?;
    store.commit()?;

    // ---- report ----
    progress("Enumerating listening sockets…");
    let listener_list = listeners::enumerate_listeners().unwrap_or_default();

    progress("Building report…");
    // persist bucket labels so they survive across runs
    for (id, label) in &bucket_labels {
        let _ = store.set_bucket_label(id, label);
    }
    let all_usage = store.all_usage()?;
    let rows = build_rows(rules, &all_usage, &listener_list);
    let unmatched = build_unmatched(&store)?;

    let ctx = ui::AuditContext {
        hostname: hostname(),
        auditing_active: true,
        collection_started: store.get_meta("collection_started")?,
        last_ingest: store.get_meta("last_ingest")?,
        events_processed,
        unmatched_events,
        note,
    };

    Ok(AnalysisResult {
        rows,
        ctx,
        unmatched,
        listeners: listener_list,
    })
}
