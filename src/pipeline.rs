//! The analysis pipeline, callable from the UI worker thread or the
//! console (--no-ui / --enable-only) paths. Opens its own Store — SQLite
//! connections are cheap and this keeps the UI thread free of DB state.

use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::BTreeSet;
use std::path::Path;

use crate::filter_map::MappedVia;
use crate::listeners::{self, Listener};
use crate::model::RuleUsage;
use crate::store::Store;
use crate::{app_identity, audit_control, baseline_checks, event_query, filter_map, firewall_rules, ui};

pub fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
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

/// The rule table without any usage data — for the first-run screen before
/// auditing is enabled (rules + scope + current listeners are still useful).
pub fn rules_only(progress: &dyn Fn(&str)) -> Result<AnalysisResult> {
    progress("Enumerating firewall rules…");
    let rules = firewall_rules::enumerate_rules().context("enumerating firewall rules")?;
    progress("Enumerating listening sockets…");
    let listeners = listeners::enumerate_listeners().unwrap_or_default();
    let rows = rules
        .into_iter()
        .map(|rule| {
            let flags = baseline_checks::flags_for(&rule);
            let listening = listeners::listeners_for_rule(&rule, &listeners);
            let target_enabled = rule.is_enabled();
            ui::RuleRow {
                rule,
                usage: None,
                flags,
                seen_apps: Vec::new(),
                listening,
                target_enabled,
            }
        })
        .collect();
    Ok(AnalysisResult {
        rows,
        ctx: ui::AuditContext {
            collection_started: None,
            last_ingest: None,
            events_processed: 0,
            unmatched_events: 0,
            note: "Connection auditing is not enabled — no usage data exists yet. \
                   Enable it to start the collection clock."
                .to_string(),
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
        // auditing was already on (GPO or manual) before this tool first
        // ran: adopt whatever history the log still holds
        store.set_meta(
            "collection_started",
            &event_query::first_event_time()?.unwrap_or_else(now_iso),
        )?;
    }

    let checkpoint = store.checkpoint_record_id()?;
    progress("Enumerating firewall rules…");
    let rules = firewall_rules::enumerate_rules().context("enumerating firewall rules")?;
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

    progress("Enumerating WFP filters…");
    let filters = filter_map::enumerate_filters().context("enumerating WFP filters")?;
    let rule_map = filter_map::build_filter_rule_map(&filters, &rules);

    // WFP filter run-time IDs are only meaningful within one boot session:
    // the same numeric ID can name a different filter after a reboot. Events
    // are therefore resolved against the filter map of *their* session —
    // current enumeration for current-boot events, recorded mappings for
    // older ones — never across sessions.
    let boots = event_query::boot_times().unwrap_or_default();
    let current_boot = boots.last().cloned().unwrap_or_default();
    if boots.is_empty() {
        eprintln!(
            "warning: no boot markers (System log 6005) found — treating all events as the \
             current boot session; cross-boot attribution may be less precise"
        );
    }
    // boot session of an event = latest boot start <= event time
    let session_of = |ev_time: &str| -> String {
        match boots.iter().rev().find(|b| b.as_str() <= ev_time) {
            Some(b) => b.clone(),
            None => current_boot.clone(),
        }
    };

    // everything from here to the checkpoint advance is one transaction:
    // a crash rolls back cleanly and a rerun re-ingests from the old
    // checkpoint without double-counting
    store.begin()?;

    for f in &filters {
        let (rule_id, via) = match rule_map.get(&f.filter_id) {
            Some((id, via)) => (Some(id.as_str()), via.as_str()),
            None => (None, MappedVia::Unmatched.as_str()),
        };
        store.upsert_filter_mapping(f.filter_id, &current_boot, rule_id, &f.name, via, &now)?;
    }

    progress("Ingesting Security log events…");
    let device_map = app_identity::device_path_map();
    // case-insensitive rule-name index for FilterOrigin attribution
    let rule_names_ci: std::collections::HashMap<String, String> = rules
        .iter()
        .map(|r| (r.name.to_lowercase(), r.name.clone()))
        .collect();
    let mut events_processed: u64 = 0;
    let mut unmatched_events: u64 = 0;
    let mut max_record_id: Option<u64> = None;
    let mut errors: u64 = 0;
    // filter IDs repeat heavily across events; cache DB lookups for the run
    let mut historical_memo: std::collections::HashMap<(u64, String), Option<String>> =
        std::collections::HashMap::new();
    // non-rule FilterOrigin values seen per unmatched bucket, to explain
    // them in the report ("Stealth", "Query User Default", …)
    let mut unmatched_origins: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    let ingest = event_query::query_events(checkpoint, |ev| {
        events_processed += 1;
        if max_record_id.map_or(true, |m| ev.record_id > m) {
            max_record_id = Some(ev.record_id);
        }
        // most authoritative first: newer Windows builds put the rule ID
        // (or a policy-origin token) straight into the event
        let origin_hit = ev
            .filter_origin
            .as_ref()
            .and_then(|o| rule_names_ci.get(&o.to_lowercase()).cloned());
        let session = session_of(&ev.time_created);
        // then the live enumeration for current-boot events; everything
        // else (and live filters since deleted) via the per-session DB map
        let current_hit = origin_hit.or_else(|| {
            if session == current_boot {
                rule_map.get(&ev.filter_rtid).map(|(id, _)| id.clone())
            } else {
                None
            }
        });
        let rule_id = match current_hit {
            Some(id) => id,
            None => {
                let key = (ev.filter_rtid, session.clone());
                let cached = historical_memo.entry(key).or_insert_with(|| {
                    store
                        .historical_filter_rule(ev.filter_rtid, &session)
                        .ok()
                        .flatten()
                });
                match cached {
                    Some(id) => id.clone(),
                    None => {
                        unmatched_events += 1;
                        let pseudo = format!("unmatched:{}:{}", session, ev.filter_rtid);
                        if let Some(origin) = &ev.filter_origin {
                            unmatched_origins
                                .entry(pseudo.clone())
                                .or_insert_with(|| origin.clone());
                        }
                        pseudo
                    }
                }
            }
        };
        let app = app_identity::normalize_path(&ev.application, &device_map);
        if store.record_event(&rule_id, &ev, &app).is_err() {
            errors += 1;
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
    let mut all_usage = store.all_usage()?;
    let mut rows: Vec<ui::RuleRow> = Vec::new();
    for rule in rules {
        let usage = all_usage.remove(&rule.name);
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
        let listening = listeners::listeners_for_rule(&rule, &listener_list);
        let target_enabled = rule.is_enabled();
        rows.push(ui::RuleRow {
            rule,
            usage,
            flags,
            seen_apps,
            listening,
            target_enabled,
        });
    }

    let filter_names = store.filter_names().unwrap_or_default();
    let unmatched = store
        .unmatched_usage()?
        .into_iter()
        .map(|usage| {
            // rule_id shape: unmatched:<boot_session>:<filter_id>
            let rest = usage.rule_id.strip_prefix("unmatched:").unwrap_or("");
            let (session, fid) = rest.rsplit_once(':').unwrap_or(("", rest));
            // best explanation available: the enumerated filter's name,
            // else the event's own FilterOrigin token, else honesty
            let filter_name = fid
                .parse::<u64>()
                .ok()
                .and_then(|id| filter_names.get(&(id, session.to_string())).cloned())
                .or_else(|| {
                    unmatched_origins
                        .get(&usage.rule_id)
                        .map(|o| format!("origin: {o}"))
                })
                .unwrap_or_else(|| "(filter not recorded — likely from a boot with no firebreak run)".to_string());
            UnmatchedRow {
                filter_id: fid.to_string(),
                boot_session: session.to_string(),
                filter_name,
                usage,
            }
        })
        .collect();

    let ctx = ui::AuditContext {
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
