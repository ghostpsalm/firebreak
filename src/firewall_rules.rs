//! Firewall rule enumeration, mutation, and backup — via PowerShell rather
//! than the COM INetFwRule interface, deliberately: COM's INetFwRule.Name is
//! the *display* name and carries no InstanceID, while Set-NetFirewallRule
//! -Name targets the unique InstanceID we join WFP filters against. Scripts
//! are passed with -EncodedCommand to sidestep quoting entirely.

use anyhow::{bail, Context, Result};
use base64::Engine;
use chrono::Utc;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::model::RuleInfo;

fn run_powershell(script: &str) -> Result<String> {
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ])
        .output()
        .context("spawning powershell")?;
    if !out.status.success() {
        bail!(
            "powershell failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Enumerate all firewall rules with their program/port filters joined in.
/// One PowerShell round-trip; the -All filter queries avoid a per-rule
/// association lookup, which is unusably slow across ~500 rules.
pub fn enumerate_rules() -> Result<Vec<RuleInfo>> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$apps = @{}
Get-NetFirewallApplicationFilter -All | ForEach-Object { $apps[$_.InstanceID] = $_.Program }
$ports = @{}
Get-NetFirewallPortFilter -All | ForEach-Object {
    $ports[$_.InstanceID] = @{
        Protocol   = [string]$_.Protocol
        LocalPort  = (@($_.LocalPort)  -join ',')
        RemotePort = (@($_.RemotePort) -join ',')
    }
}
$out = Get-NetFirewallRule | ForEach-Object {
    $p = $ports[$_.InstanceID]
    [pscustomobject]@{
        Name        = $_.Name
        DisplayName = $_.DisplayName
        Description = $_.Description
        Enabled     = [string]$_.Enabled
        Direction   = [string]$_.Direction
        Action      = [string]$_.Action
        Profile     = [string]$_.Profile
        Group       = $_.Group
        Program     = $apps[$_.InstanceID]
        Protocol    = $p.Protocol
        LocalPort   = $p.LocalPort
        RemotePort  = $p.RemotePort
    }
}
ConvertTo-Json -InputObject @($out) -Compress -Depth 3
"#;
    let json = run_powershell(script)?;
    let rules: Vec<RuleInfo> =
        serde_json::from_str(json.trim()).context("parsing Get-NetFirewallRule JSON")?;
    Ok(rules)
}

/// Directory where backups land: %ProgramData%\firebreak\backups
pub fn backup_dir() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    Path::new(&base).join("firebreak").join("backups")
}

/// Export the full firewall policy before any mutation. Produces a
/// restorable .wfw (netsh advfirewall import) plus a JSON rule dump for
/// human-readable diffing. Returns the .wfw path.
pub fn backup_policy(rules: &[RuleInfo]) -> Result<PathBuf> {
    let dir = backup_dir();
    crate::secure_dir::ensure_secured_dir(&dir)?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let wfw = dir.join(format!("firewall-{stamp}.wfw"));
    let json = dir.join(format!("rules-{stamp}.json"));

    let out = Command::new("netsh")
        .args(["advfirewall", "export", &wfw.to_string_lossy()])
        .output()
        .context("running netsh advfirewall export")?;
    if !out.status.success() {
        bail!(
            "netsh export failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    std::fs::write(&json, serde_json::to_string_pretty(rules)?)?;
    Ok(wfw)
}

/// Enable/disable rules by unique Name (InstanceID). Backup first — this
/// module doesn't do it for you; the UI's Apply flow does.
pub fn set_rules_enabled(rule_names: &[String], enabled: bool) -> Result<()> {
    if rule_names.is_empty() {
        return Ok(());
    }
    let list = rule_names
        .iter()
        .map(|n| format!("'{}'", n.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let value = if enabled { "True" } else { "False" };
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
Set-NetFirewallRule -Name @({list}) -Enabled {value}
"#
    );
    run_powershell(&script)?;
    Ok(())
}
