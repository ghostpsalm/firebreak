#![cfg_attr(windows, windows_subsystem = "windows")]

mod app_identity;
mod audit_control;
mod baseline_checks;
mod console;
mod elevation;
mod event_query;
mod filter_map;
mod firewall_rules;
mod listeners;
mod model;
mod pipeline;
mod preview;
mod scope;
mod secure_dir;
mod store;
mod support;
mod syspath;
mod theme;
mod time_util;
mod ui;
mod update;

use anyhow::{bail, Result};

use store::Store;

struct Args {
    enable_only: bool,
    no_ui: bool,
    dump_filters: bool,
    export_support: bool,
    ui_preview: bool,
    restore_audit: bool,
    reset: bool,
    db_path: std::path::PathBuf,
}

fn parse_args() -> Args {
    let mut args = Args {
        enable_only: false,
        no_ui: false,
        dump_filters: false,
        export_support: false,
        ui_preview: false,
        restore_audit: false,
        reset: false,
        db_path: store::default_db_path(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--enable-only" => args.enable_only = true,
            "--no-ui" => args.no_ui = true,
            "--dump-filters" => args.dump_filters = true,
            "--export-support" => args.export_support = true,
            "--ui-preview" => args.ui_preview = true,
            "--restore-audit" => args.restore_audit = true,
            "--reset" => args.reset = true,
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
                     Run without arguments for the app: it boots to the rule table, offers an\n\
                     'Enable connection auditing' button on first run, and on later runs\n\
                     ingests new 5156/5157 events and correlates them to firewall rules.\n\n\
                     Options:\n\
                     \x20 --enable-only    enable auditing + snapshot rules, then exit (headless)\n\
                     \x20 --no-ui          ingest and print a text report instead of the UI\n\
                     \x20 --dump-filters   dump the live WFP filter table (for verifying\n\
                     \x20                  the filter->rule mapping) and exit\n\
                     \x20 --export-support write a full diagnostic bundle to the Desktop\n\
                     \x20                  (audit state, rules, filters, event attribution probe)\n\
                     \x20 --restore-audit  restore the audit policy and Security log size\n\
                     \x20                  recorded before firebreak first changed them\n\
                     \x20 --reset          clear collected usage + checkpoint; next run\n\
                     \x20                  re-scans the whole Security log\n\
                     \x20 --ui-preview     open the UI with mock data (no elevation needed)\n\
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
    // GUI-subsystem binary: reattach to the parent terminal so CLI flags
    // still print when run from a shell
    console::attach_parent_console();
    let args = parse_args();

    if args.ui_preview {
        return preview::run();
    }

    // clear a leftover exe image from a prior self-update
    update::cleanup_old();

    if !elevation::is_elevated() {
        // the embedded manifest normally forces a UAC prompt at launch;
        // this is the fallback when the process was started some other way
        if elevation::relaunch_elevated() {
            return Ok(());
        }
        bail!(
            "firebreak must run elevated (audit policy, Security log and WFP access all \
             require it). The elevation prompt was declined or unavailable."
        );
    }

    if args.dump_filters {
        return dump_filters();
    }
    if args.export_support {
        let path = support::default_path();
        support::export(&path)?;
        println!("Support bundle written to:\n  {}", path.display());
        println!("Review/redact if needed, then send it back for diagnosis.");
        return Ok(());
    }
    if args.restore_audit {
        let store = Store::open(&args.db_path)?;
        return restore_audit(&store);
    }
    if args.reset {
        pipeline::reset(&args.db_path)?;
        println!("Cleared usage data and checkpoint. The next run re-scans the whole Security log.");
        return Ok(());
    }
    if args.enable_only {
        pipeline::enable_collection(&args.db_path, &|s: &str| println!("{s}"))?;
        println!(
            "--enable-only: auditing is enabled. Run firebreak again later to analyze.\n\
             Note: local audit policy can be overridden by Group Policy on refresh; \
             re-check with: auditpol /get /subcategory:{}",
            audit_control::FILTERING_PLATFORM_CONNECTION_GUID
        );
        return Ok(());
    }
    if args.no_ui {
        if !pipeline::audit_enabled()? {
            pipeline::enable_collection(&args.db_path, &|s: &str| println!("{s}"))?;
            println!(
                "Auditing was not enabled — collection starts now; there is no retroactive \
                 data. Run again later to analyze."
            );
            return Ok(());
        }
        let result = pipeline::analyze(&args.db_path, &|s: &str| println!("{s}"))?;
        println!(
            "Ingested {} events ({} unattributed to a rule).",
            result.ctx.events_processed, result.ctx.unmatched_events
        );
        return print_text_report(&result);
    }

    // default: boot straight to the window; audit detection / enablement /
    // analysis run on background workers inside the app
    ui::run_live(args.db_path)
}

/// Put the host's audit configuration back to what was recorded before
/// firebreak first changed it (S-06). Collected usage data is left untouched.
fn restore_audit(store: &Store) -> Result<()> {
    println!("{}", pipeline::restore_audit_state(store)?);
    Ok(())
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
    eprintln!(
        "{} filters. Cross-check a FilterRTID from a 5156 event against this list.",
        filters.len()
    );
    Ok(())
}

fn print_text_report(result: &pipeline::AnalysisResult) -> Result<()> {
    let rows = &result.rows;
    let mut sorted: Vec<&ui::RuleRow> = rows.iter().collect();
    sorted.sort_by_key(|r| r.total_hits());

    println!("\n=== Zero-hit enabled rules (disable candidates) ===");
    for r in sorted.iter().filter(|r| r.rule.is_enabled() && r.total_hits() == 0) {
        println!(
            "  {} [{}] {} {} — scope: {}",
            r.rule.display_name,
            r.rule.direction,
            r.rule.action,
            r.rule.profile,
            listeners::scope_summary(&r.rule)
        );
    }

    println!("\n=== Used rules (most hits first) ===");
    for r in sorted.iter().rev() {
        if let Some(u) = r.usage.as_ref().filter(|u| u.allow_count + u.block_count > 0) {
            println!(
                "  {:>8} allow / {:>6} block  {}  last {}  apps: {}{}",
                u.allow_count,
                u.block_count,
                r.rule.display_name,
                u.last_seen.as_deref().unwrap_or("-"),
                r.seen_apps.join(", "),
                if r.listening.is_empty() {
                    String::new()
                } else {
                    format!("  listening: {}", r.listening.join(", "))
                }
            );
        }
    }

    println!("\n=== Baseline flags ===");
    for r in rows.iter().filter(|r| !r.flags.is_empty() && r.rule.is_enabled()) {
        for f in &r.flags {
            println!("  [{}] {} — {}", f.title, r.rule.display_name, f.advice);
        }
    }

    if !result.unmatched.is_empty() {
        println!("\n=== Unattributed events (top 20) ===");
        println!(
            "(WFP filters that are not firewall rules — e.g. default block policy — or \
             filters from boots with no firebreak run)"
        );
        for u in result.unmatched.iter().take(20) {
            println!(
                "  {} [filter {} @ {}]: {} allow / {} block, apps: {}",
                u.filter_name,
                u.filter_id,
                u.boot_session.get(..10).unwrap_or(&u.boot_session),
                u.usage.allow_count,
                u.usage.block_count,
                u.usage
                    .apps
                    .iter()
                    .take(3)
                    .map(|(p, _)| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    if !result.listeners.is_empty() {
        println!("\n=== Active listening sockets ===");
        let mut sorted: Vec<_> = result.listeners.iter().collect();
        sorted.sort_by_key(|l| (l.proto.clone(), l.local_port));
        for l in sorted {
            println!(
                "  {:<4} {:>21}  {} (pid {})",
                l.proto,
                format!("{}:{}", l.local_address, l.local_port),
                if l.process_name.is_empty() { "?" } else { &l.process_name },
                l.pid
            );
        }
    }
    Ok(())
}
