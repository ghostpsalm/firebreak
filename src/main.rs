mod app_identity;
mod audit_control;
mod baseline_checks;
mod elevation;
mod event_query;
mod filter_map;
mod firewall_rules;
mod model;
mod store;
mod ui;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use std::collections::BTreeSet;

use filter_map::MappedVia;
use store::Store;

fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

struct Args {
    enable_only: bool,
    no_ui: bool,
    dump_filters: bool,
    ui_preview: bool,
    db_path: std::path::PathBuf,
}

fn parse_args() -> Args {
    let mut args = Args {
        enable_only: false,
        no_ui: false,
        dump_filters: false,
        ui_preview: false,
        db_path: store::default_db_path(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--enable-only" => args.enable_only = true,
            "--no-ui" => args.no_ui = true,
            "--dump-filters" => args.dump_filters = true,
            "--ui-preview" => args.ui_preview = true,
            "--db" => match it.next() {
                Some(p) => args.db_path = p.into(),
                None => {
                    eprintln!("--db requires a path argument");
                    std::process::exit(2);
                }
            },
            "--help" | "-h" => {
                println!(
                    "firebreak — Windows Firewall rule-usage auditor\n\n\
                     Modes are auto-detected: first run enables WFP connection auditing\n\
                     and starts the collection clock; later runs ingest new 5156/5157\n\
                     events, correlate them to firewall rules, and open the report UI.\n\n\
                     Options:\n\
                     \x20 --enable-only    enable auditing + snapshot rules, then exit\n\
                     \x20 --no-ui          ingest and print a text report instead of the UI\n\
                     \x20 --dump-filters   dump the live WFP filter table (for verifying\n\
                     \x20                  the filter->rule mapping) and exit\n\
                     \x20 --db <path>      database path (default %ProgramData%\\firebreak\\firebreak.db)"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other} (see --help)");
                std::process::exit(2);
            }
        }
    }
    args
}

fn main() -> Result<()> {
    let args = parse_args();

    if args.ui_preview {
        return ui_preview();
    }

    if !elevation::is_elevated() {
        bail!(
            "firebreak must run elevated (audit policy, Security log and WFP access all \
             require it). Right-click -> Run as administrator, or start from an elevated terminal."
        );
    }

    if args.dump_filters {
        return dump_filters();
    }

    let store = Store::open(&args.db_path)?;

    // ---- mode detection: is auditing on? ----
    let audit_state = audit_control::query_audit_state()?;
    let mut note = String::new();
    if !audit_state.fully_enabled() {
        println!(
            "Filtering Platform Connection auditing is not (fully) enabled — enabling now. \
             Collection starts from this moment; there is no retroactive data."
        );
        audit_control::enable_auditing()?;
        match audit_control::ensure_security_log_size(audit_control::DEFAULT_SECURITY_LOG_BYTES) {
            Ok(true) => println!(
                "Security log max size raised to {} MiB.",
                audit_control::DEFAULT_SECURITY_LOG_BYTES / 1024 / 1024
            ),
            Ok(false) => {}
            Err(e) => eprintln!("warning: could not resize Security log: {e:#}"),
        }
        let now = now_iso();
        if store.get_meta("collection_started")?.is_none() {
            store.set_meta("collection_started", &now)?;
        }
        if store.checkpoint_record_id()?.is_none() {
            // start the cursor at the newest existing record so pre-enable
            // history (from any earlier auditing period) isn't swept in;
            // that adoption path is the explicit no-checkpoint mode below
            let start = event_query::newest_record_id()?.unwrap_or(0);
            store.set_checkpoint_record_id(start)?;
        }
        // snapshot the rule set as it stood when the clock started
        match firewall_rules::enumerate_rules() {
            Ok(rules) => {
                store.snapshot_rules(&rules, &now)?;
                println!("Snapshotted {} rules. Audit clock started at {now}.", rules.len());
            }
            Err(e) => eprintln!("warning: rule snapshot failed: {e:#}"),
        }
        println!(
            "Note: local audit policy can be overridden by Group Policy on refresh; \
             if events stop appearing, re-check with: auditpol /get /subcategory:{}",
            audit_control::FILTERING_PLATFORM_CONNECTION_GUID
        );
        note = "Collection just started — usage data will be empty until traffic accumulates."
            .to_string();
    } else if store.checkpoint_record_id()?.is_none() {
        // auditing was already on (GPO or manual) before this tool first ran:
        // adopt whatever history the log still holds
        println!("Auditing already enabled but no local checkpoint — ingesting available history.");
        store.set_meta(
            "collection_started",
            &event_query::first_event_time()?.unwrap_or_else(now_iso),
        )?;
    }

    // exits here whether auditing was just enabled or already on — the flag
    // promises "ensure collection is running, don't analyze"
    if args.enable_only {
        println!("--enable-only: auditing is enabled. Run firebreak again later to analyze.");
        return Ok(());
    }

    // ---- ingest ----
    let checkpoint = store.checkpoint_record_id()?;
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

    let device_map = app_identity::device_path_map();
    let mut events_processed: u64 = 0;
    let mut unmatched_events: u64 = 0;
    let mut max_record_id: Option<u64> = None;
    let mut errors: u64 = 0;
    // filter IDs repeat heavily across events; cache DB lookups for the run
    let mut historical_memo: std::collections::HashMap<(u64, String), Option<String>> =
        std::collections::HashMap::new();

    let ingest = event_query::query_events(checkpoint, |ev| {
        events_processed += 1;
        if max_record_id.map_or(true, |m| ev.record_id > m) {
            max_record_id = Some(ev.record_id);
        }
        let session = session_of(&ev.time_created);
        // current-boot events use the live enumeration; everything else (and
        // live filters since deleted) goes through the per-session DB map
        let current_hit = if session == current_boot {
            rule_map.get(&ev.filter_rtid).map(|(id, _)| id.clone())
        } else {
            None
        };
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
                        format!("unmatched:{}:{}", session, ev.filter_rtid)
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

    println!(
        "Ingested {events_processed} events ({unmatched_events} unattributed to a rule)."
    );

    // ---- report ----
    let mut rows: Vec<ui::RuleRow> = Vec::with_capacity(rules.len());
    for rule in rules {
        let usage = store.usage_for(&rule.name)?;
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
        let target_enabled = rule.is_enabled();
        rows.push(ui::RuleRow {
            rule,
            usage,
            flags,
            seen_apps,
            target_enabled,
        });
    }

    let ctx_info = ui::AuditContext {
        collection_started: store.get_meta("collection_started")?,
        last_ingest: store.get_meta("last_ingest")?,
        events_processed,
        unmatched_events,
        note,
    };

    if args.no_ui {
        print_text_report(&rows, &store)?;
        return Ok(());
    }
    ui::run(rows, ctx_info)
}

/// Launch the UI with representative mock data — for developing/reviewing
/// the interface without a Windows box or collected data.
fn ui_preview() -> Result<()> {
    use model::{RuleInfo, RuleUsage};

    fn rule(
        name: &str, display: &str, enabled: bool, dir: &str, action: &str, profile: &str,
        group: Option<&str>, program: Option<&str>, proto: Option<&str>, lport: Option<&str>,
    ) -> RuleInfo {
        RuleInfo {
            name: name.into(),
            display_name: display.into(),
            description: None,
            enabled: if enabled { "True" } else { "False" }.into(),
            direction: dir.into(),
            action: action.into(),
            profile: profile.into(),
            group: group.map(Into::into),
            program: program.map(Into::into),
            protocol: proto.map(Into::into),
            local_port: lport.map(Into::into),
            remote_port: None,
        }
    }
    fn usage(id: &str, allow: i64, block: i64, last: &str, apps: &[(&str, i64)]) -> RuleUsage {
        RuleUsage {
            rule_id: id.into(),
            allow_count: allow,
            block_count: block,
            first_seen: Some("2026-07-01T08:02:11.000Z".into()),
            last_seen: Some(last.into()),
            apps: apps.iter().map(|(p, h)| (p.to_string(), *h)).collect(),
        }
    }

    let specs: Vec<(RuleInfo, Option<RuleUsage>, Vec<&str>)> = vec![
        (
            rule("{a1}", "Core Networking - DNS (UDP-Out)", true, "Outbound", "Allow", "Any",
                Some("Core Networking"), Some(r"%SystemRoot%\system32\svchost.exe"), Some("UDP"), Some("Any")),
            Some(usage("{a1}", 48213, 0, "2026-07-15T18:41:02.113Z",
                &[(r"C:\Windows\System32\svchost.exe", 48213)])),
            vec!["Host Process for Windows Services (Microsoft Corporation)"],
        ),
        (
            rule("{a2}", "Google Chrome (mDNS-In)", true, "Inbound", "Allow", "Any",
                Some("Google Chrome"), Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                Some("UDP"), Some("5353")),
            Some(usage("{a2}", 1522, 0, "2026-07-15T17:12:44.902Z",
                &[(r"C:\Program Files\Google\Chrome\Application\chrome.exe", 1522)])),
            vec!["Google Chrome (Google LLC)"],
        ),
        (
            rule("{a3}", "Remote Desktop - User Mode (TCP-In)", true, "Inbound", "Allow", "Any",
                Some("Remote Desktop"), None, Some("TCP"), Some("3389")),
            None,
            vec![],
        ),
        (
            rule("{a4}", "File and Printer Sharing (SMB-In)", true, "Inbound", "Allow", "Private",
                Some("File and Printer Sharing"), Some("System"), Some("TCP"), Some("445")),
            Some(usage("{a4}", 12, 0, "2026-07-09T10:03:19.000Z", &[("System", 12)])),
            vec!["System"],
        ),
        (
            rule("{a5}", "Spotify", true, "Outbound", "Allow", "Any", None,
                Some(r"%USERPROFILE%\AppData\Roaming\Spotify\Spotify.exe"), Some("TCP"), None),
            Some(usage("{a5}", 9214, 0, "2026-07-15T18:20:00.000Z",
                &[(r"%USERPROFILE%\AppData\Roaming\Spotify\Spotify.exe", 9214)])),
            vec!["Spotify (Spotify AB)"],
        ),
        (
            rule("{a6}", "LegacyVPN Client", true, "Inbound", "Allow", "Any", None,
                Some(r"C:\Program Files (x86)\LegacyVPN\vpngui.exe"), Some("UDP"), Some("500,4500")),
            None,
            vec![],
        ),
        (
            rule("{a7}", "MyApp Server", true, "Inbound", "Allow", "Any", None, None, None, None),
            Some(usage("{a7}", 302, 88, "2026-07-15T16:55:31.000Z",
                &[(r"C:\Tools\myapp\server.exe", 390)])),
            vec!["server.exe"],
        ),
        (
            rule("{a8}", "Block uTorrent", true, "Outbound", "Block", "Any", None,
                Some(r"%USERPROFILE%\AppData\Local\uTorrent\uTorrent.exe"), None, None),
            Some(usage("{a8}", 0, 4411, "2026-07-15T12:00:09.000Z",
                &[(r"%USERPROFILE%\AppData\Local\uTorrent\uTorrent.exe", 4411)])),
            vec!["µTorrent (BitTorrent Inc.)"],
        ),
        (
            rule("{a9}", "Network Discovery (SSDP-In)", true, "Inbound", "Allow", "Private",
                Some("Network Discovery"), Some(r"%SystemRoot%\system32\svchost.exe"),
                Some("UDP"), Some("1900")),
            Some(usage("{a9}", 233, 0, "2026-07-14T21:38:55.000Z",
                &[(r"C:\Windows\System32\svchost.exe", 233)])),
            vec!["Host Process for Windows Services (Microsoft Corporation)"],
        ),
        (
            rule("{a10}", "Old Printer Utility", false, "Inbound", "Allow", "Any", None,
                Some(r"C:\Program Files\HP\printerutil.exe"), Some("TCP"), Some("9100")),
            None,
            vec![],
        ),
    ];

    let rows = specs
        .into_iter()
        .map(|(rule, usage, apps)| {
            let flags = baseline_checks::flags_for(&rule);
            let target_enabled = rule.is_enabled();
            ui::RuleRow {
                rule,
                usage,
                flags,
                seen_apps: apps.into_iter().map(Into::into).collect(),
                target_enabled,
            }
        })
        .collect();

    ui::run(
        rows,
        ui::AuditContext {
            collection_started: Some("2026-07-01T08:00:00.000Z".into()),
            last_ingest: Some("2026-07-15T18:45:12.000Z".into()),
            events_processed: 184_232,
            unmatched_events: 1_240,
            note: String::new(),
        },
    )
}

fn dump_filters() -> Result<()> {
    let filters = filter_map::enumerate_filters()?;
    println!("filter_id\tname\tprovider_context_key\tprovider_data_utf16\tprovider_data_hex");
    for f in &filters {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            f.filter_id, f.name, f.provider_context_key, f.provider_data_utf16, f.provider_data_hex
        );
    }
    eprintln!("{} filters. Cross-check a FilterRTID from a 5156 event against this list.", filters.len());
    Ok(())
}

fn print_text_report(rows: &[ui::RuleRow], store: &Store) -> Result<()> {
    let mut sorted: Vec<&ui::RuleRow> = rows.iter().collect();
    sorted.sort_by_key(|r| r.total_hits());

    println!("\n=== Zero-hit enabled rules (disable candidates) ===");
    for r in sorted.iter().filter(|r| r.rule.is_enabled() && r.total_hits() == 0) {
        println!("  {} [{}] {} {}", r.rule.display_name, r.rule.direction, r.rule.action, r.rule.profile);
    }

    println!("\n=== Used rules (most hits first) ===");
    for r in sorted.iter().rev() {
        if let Some(u) = r.usage.as_ref().filter(|u| u.allow_count + u.block_count > 0) {
            println!(
                "  {:>8} allow / {:>6} block  {}  last {}  apps: {}",
                u.allow_count,
                u.block_count,
                r.rule.display_name,
                u.last_seen.as_deref().unwrap_or("-"),
                r.seen_apps.join(", ")
            );
        }
    }

    println!("\n=== Baseline flags ===");
    for r in rows.iter().filter(|r| !r.flags.is_empty() && r.rule.is_enabled()) {
        for f in &r.flags {
            println!("  [{}] {} — {}", f.title, r.rule.display_name, f.advice);
        }
    }

    let unmatched = store.unmatched_usage()?;
    if !unmatched.is_empty() {
        println!("\n=== Events not attributed to any firewall rule (top 20) ===");
        println!("(WFP default/stealth filters, or filter IDs from an earlier boot — see README)");
        for u in unmatched.iter().take(20) {
            println!(
                "  {}: {} allow / {} block, apps: {}",
                u.rule_id,
                u.allow_count,
                u.block_count,
                u.apps.iter().take(3).map(|(p, _)| p.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
    }
    Ok(())
}
