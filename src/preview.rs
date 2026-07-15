//! `--ui-preview`: launch the UI with representative mock data — for
//! developing/reviewing the interface without a Windows box or collected
//! data. Runs unelevated and touches no Windows APIs.

use anyhow::Result;

use crate::listeners::Listener;
use crate::pipeline::UnmatchedRow;
use crate::{baseline_checks, listeners, ui};

/// Launch the UI with representative mock data — for developing/reviewing
/// the interface without a Windows box or collected data.
pub fn run() -> Result<()> {
    use crate::model::{RuleInfo, RuleUsage};

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
            rule("{a3}", "Remote Desktop - User Mode (TCP-In)", true, "Inbound", "Allow", "Domain",
                Some("Remote Desktop"), None, Some("TCP"), Some("3389")),
            None,
            vec![],
        ),
        (
            rule("{a4}", "File and Printer Sharing (SMB-In)", true, "Inbound", "Allow", "Domain, Private",
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

    let mut specs = specs;
    specs[0].0.description =
        Some("Outbound rule to allow DNS requests. DNS responses based on requests that \
              matched this rule will be permitted regardless of source address."
            .into());
    specs[2].0.description =
        Some("Inbound rule for the Remote Desktop service to allow RDP traffic. [TCP 3389]".into());

    fn mock_listener(proto: &str, addr: &str, port: u32, pid: u32, name: &str, path: &str) -> Listener {
        Listener {
            proto: proto.into(),
            local_address: addr.into(),
            local_port: port,
            pid,
            process_name: name.into(),
            process_path: path.into(),
        }
    }
    let mock_listeners = vec![
        mock_listener("TCP", "0.0.0.0", 3389, 1104, "svchost", r"C:\Windows\System32\svchost.exe"),
        mock_listener("TCP", "0.0.0.0", 445, 4, "System", ""),
        mock_listener("TCP", "127.0.0.1", 9100, 5522, "printerutil", r"C:\Program Files\HP\printerutil.exe"),
        mock_listener("UDP", "0.0.0.0", 5353, 7810, "chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        mock_listener("UDP", "0.0.0.0", 1900, 1220, "svchost", r"C:\Windows\System32\svchost.exe"),
        mock_listener("TCP", "0.0.0.0", 135, 948, "svchost", r"C:\Windows\System32\svchost.exe"),
    ];

    let rows = specs
        .into_iter()
        .map(|(rule, usage, apps)| {
            let flags = baseline_checks::flags_for(&rule);
            let listening = listeners::listeners_for_rule(&rule, &mock_listeners);
            let target_enabled = rule.is_enabled();
            ui::RuleRow {
                rule,
                usage,
                flags,
                seen_apps: apps.into_iter().map(Into::into).collect(),
                listening,
                target_enabled,
            }
        })
        .collect();

    // what a ping/nmap session looks like: blocked traffic lands on WFP's
    // built-in default block filters, not on firewall rules
    let unmatched = vec![
        UnmatchedRow {
            filter_id: "68231".into(),
            boot_session: "2026-07-14T07:58:03.1204418Z".into(),
            filter_name: "Default Inbound Block".into(),
            usage: RuleUsage {
                rule_id: "unmatched:2026-07-14T07:58:03.1204418Z:68231".into(),
                allow_count: 0,
                block_count: 486,
                first_seen: Some("2026-07-15T09:12:00.000Z".into()),
                last_seen: Some("2026-07-15T09:14:31.000Z".into()),
                apps: vec![("System".into(), 486)],
            },
        },
        UnmatchedRow {
            filter_id: "67810".into(),
            boot_session: "2026-07-14T07:58:03.1204418Z".into(),
            filter_name: "ICMP Echo Request v6 Default Block".into(),
            usage: RuleUsage {
                rule_id: "unmatched:2026-07-14T07:58:03.1204418Z:67810".into(),
                allow_count: 0,
                block_count: 37,
                first_seen: Some("2026-07-15T09:10:02.000Z".into()),
                last_seen: Some("2026-07-15T09:10:44.000Z".into()),
                apps: vec![("System".into(), 37)],
            },
        },
    ];

    ui::run_preview(
        rows,
        ui::AuditContext {
            collection_started: Some("2026-07-01T08:00:00.000Z".into()),
            last_ingest: Some("2026-07-15T18:45:12.000Z".into()),
            events_processed: 184_232,
            unmatched_events: 523,
            note: String::new(),
        },
        unmatched,
        mock_listeners,
    )
}
