//! Current listening sockets (netstat-style), enumerated via
//! Get-NetTCPConnection/-NetUDPEndpoint with owning-process resolution, and
//! cross-referenced against inbound rules so the table can show which
//! process is actually bound to a rule's ports right now.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::model::RuleInfo;

#[derive(Debug, Clone, Deserialize)]
pub struct Listener {
    #[serde(rename = "Proto")]
    pub proto: String,
    #[serde(rename = "LocalAddress")]
    pub local_address: String,
    #[serde(rename = "LocalPort")]
    pub local_port: u32,
    #[serde(rename = "Pid")]
    pub pid: u32,
    #[serde(rename = "ProcessName", default)]
    pub process_name: String,
    #[serde(rename = "ProcessPath", default)]
    pub process_path: String,
}

pub fn enumerate_listeners() -> Result<Vec<Listener>> {
    let script = r#"
$ErrorActionPreference = 'SilentlyContinue'
$procs = @{}
Get-Process | ForEach-Object { $procs[[int]$_.Id] = @{ Name = $_.ProcessName; Path = $_.Path } }
$out = @()
Get-NetTCPConnection -State Listen | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    $out += [pscustomobject]@{
        Proto = 'TCP'; LocalAddress = [string]$_.LocalAddress; LocalPort = [int]$_.LocalPort
        Pid = [int]$_.OwningProcess; ProcessName = [string]$p.Name; ProcessPath = [string]$p.Path
    }
}
Get-NetUDPEndpoint | ForEach-Object {
    $p = $procs[[int]$_.OwningProcess]
    $out += [pscustomobject]@{
        Proto = 'UDP'; LocalAddress = [string]$_.LocalAddress; LocalPort = [int]$_.LocalPort
        Pid = [int]$_.OwningProcess; ProcessName = [string]$p.Name; ProcessPath = [string]$p.Path
    }
}
ConvertTo-Json -InputObject @($out) -Compress
"#;
    let json = crate::firewall_rules::run_powershell(script)?;
    let listeners: Vec<Listener> =
        serde_json::from_str(json.trim()).context("parsing listener JSON")?;
    Ok(listeners)
}

/// Expand the couple of env-var forms Windows rules commonly use in Program
/// paths, enough for basename comparison.
fn expand_program_path(p: &str) -> String {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    p.replace("%SystemRoot%", &system_root)
        .replace("%systemroot%", &system_root)
        .replace("%windir%", &system_root)
        .to_lowercase()
}

fn basename(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Which current listeners fall under an inbound rule's scope — by port
/// (protocol + local port list; numeric entries only, ranges are skipped)
/// or, when the rule is port-unrestricted, by program path/name.
pub fn listeners_for_rule(rule: &RuleInfo, listeners: &[Listener]) -> Vec<String> {
    if !rule.direction.eq_ignore_ascii_case("inbound") {
        return Vec::new();
    }
    let rule_proto = rule.protocol.as_deref().unwrap_or("Any");
    let ports: Vec<u32> = rule
        .local_port
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();
    let program = rule
        .program
        .as_deref()
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("any"))
        .map(expand_program_path);

    let mut out = Vec::new();
    for l in listeners {
        let proto_ok =
            rule_proto.eq_ignore_ascii_case("any") || rule_proto.eq_ignore_ascii_case(&l.proto);
        if !proto_ok {
            continue;
        }
        let port_hit = ports.contains(&l.local_port);
        let program_hit = match &program {
            Some(prog) => {
                let lp = l.process_path.to_lowercase();
                !lp.is_empty()
                    && (lp == *prog || basename(&lp) == basename(prog))
            }
            None => false,
        };
        // port-scoped rules match on port; port-unrestricted program rules
        // match on the owning process
        let hit = if !ports.is_empty() { port_hit } else { program_hit };
        if hit {
            let name = if l.process_name.is_empty() {
                format!("pid {}", l.pid)
            } else {
                l.process_name.clone()
            };
            let entry = format!("{} :{}/{}", name, l.local_port, l.proto);
            if !out.contains(&entry) {
                out.push(entry);
            }
        }
    }
    out
}

/// Compact scope string for the table column: protocol, local ports, and
/// program basename. "Any" scope renders as "Any".
pub fn scope_summary(rule: &RuleInfo) -> String {
    let mut parts: Vec<String> = Vec::new();
    let proto = rule.protocol.as_deref().unwrap_or("");
    let ports = rule.local_port.as_deref().unwrap_or("");
    if !proto.is_empty() && !proto.eq_ignore_ascii_case("any") {
        if ports.is_empty() || ports.eq_ignore_ascii_case("any") {
            parts.push(proto.to_string());
        } else {
            parts.push(format!("{proto} {ports}"));
        }
    } else if !ports.is_empty() && !ports.eq_ignore_ascii_case("any") {
        parts.push(ports.to_string());
    }
    if let Some(prog) = rule
        .program
        .as_deref()
        .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("any"))
    {
        parts.push(basename(prog).to_string());
    }
    if parts.is_empty() {
        "Any".to_string()
    } else {
        parts.join(" • ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(dir: &str, proto: Option<&str>, lport: Option<&str>, program: Option<&str>) -> RuleInfo {
        RuleInfo {
            name: "{id}".into(),
            display_name: "r".into(),
            description: None,
            enabled: "True".into(),
            direction: dir.into(),
            action: "Allow".into(),
            profile: "Any".into(),
            group: None,
            program: program.map(Into::into),
            protocol: proto.map(Into::into),
            local_port: lport.map(Into::into),
            remote_port: None,
        }
    }

    fn listener(proto: &str, port: u32, name: &str, path: &str) -> Listener {
        Listener {
            proto: proto.into(),
            local_address: "0.0.0.0".into(),
            local_port: port,
            pid: 1234,
            process_name: name.into(),
            process_path: path.into(),
        }
    }

    #[test]
    fn port_scoped_rule_matches_listener_on_port_and_proto() {
        let ls = vec![
            listener("TCP", 3389, "svchost", r"C:\Windows\System32\svchost.exe"),
            listener("UDP", 3389, "other", ""),
        ];
        let r = rule("Inbound", Some("TCP"), Some("3389"), None);
        assert_eq!(listeners_for_rule(&r, &ls), vec!["svchost :3389/TCP"]);
    }

    #[test]
    fn program_rule_without_ports_matches_by_process() {
        let ls = vec![listener("UDP", 5353, "chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe")];
        let r = rule("Inbound", Some("UDP"), None, Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe"));
        assert_eq!(listeners_for_rule(&r, &ls), vec!["chrome :5353/UDP"]);
    }

    #[test]
    fn outbound_rules_have_no_listeners() {
        let ls = vec![listener("TCP", 443, "x", "")];
        let r = rule("Outbound", Some("TCP"), Some("443"), None);
        assert!(listeners_for_rule(&r, &ls).is_empty());
    }

    #[test]
    fn scope_summary_is_compact() {
        assert_eq!(scope_summary(&rule("Inbound", Some("TCP"), Some("3389"), None)), "TCP 3389");
        assert_eq!(
            scope_summary(&rule("Inbound", Some("UDP"), Some("5353"), Some(r"C:\x\chrome.exe"))),
            "UDP 5353 • chrome.exe"
        );
        assert_eq!(scope_summary(&rule("Inbound", None, None, None)), "Any");
        assert_eq!(
            scope_summary(&rule("Outbound", None, None, Some(r"C:\y\spotify.exe"))),
            "spotify.exe"
        );
    }
}
