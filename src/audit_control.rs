//! Query/enable the "Filtering Platform Connection" audit subcategory and
//! size the Security event log.
//!
//! Query goes through AuditQuerySystemPolicy (locale-independent).
//! Set shells out to auditpol.exe by subcategory GUID — auditpol handles the
//! SeSecurityPrivilege dance for us and the GUID form avoids localized
//! subcategory names.

use anyhow::{bail, Context, Result};

#[cfg(windows)]
use windows::core::GUID;
#[cfg(windows)]
use windows::Win32::Security::Authentication::Identity::{
    AuditFree, AuditQuerySystemPolicy, AUDIT_POLICY_INFORMATION,
};

/// Audit subcategory: Filtering Platform Connection (events 5156/5157).
/// NOT "Filtering Platform Packet Drop" ({0CCE9225-...}) — that one is
/// per-packet volume and must stay off.
pub const FILTERING_PLATFORM_CONNECTION_GUID: &str = "{0CCE9226-69AE-11D9-BED3-505054503030}";

#[cfg(windows)]
const SUBCATEGORY: GUID = GUID::from_u128(0x0CCE9226_69AE_11D9_BED3_505054503030);

const POLICY_AUDIT_EVENT_SUCCESS: u32 = 0x1;
const POLICY_AUDIT_EVENT_FAILURE: u32 = 0x2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditState {
    pub success: bool,
    pub failure: bool,
}

impl AuditState {
    pub fn fully_enabled(&self) -> bool {
        self.success && self.failure
    }
}

#[cfg(windows)]
pub fn query_audit_state() -> Result<AuditState> {
    unsafe {
        let mut policy: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
        let ok = AuditQuerySystemPolicy(&[SUBCATEGORY], &mut policy);
        if !ok.as_bool() || policy.is_null() {
            bail!(
                "AuditQuerySystemPolicy failed ({}); is the process elevated?",
                windows::core::Error::from_win32()
            );
        }
        let info = *policy;
        AuditFree(policy as *mut _);
        Ok(AuditState {
            success: info.AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS != 0,
            failure: info.AuditingInformation & POLICY_AUDIT_EVENT_FAILURE != 0,
        })
    }
}

#[cfg(not(windows))]
pub fn query_audit_state() -> Result<AuditState> {
    bail!("audit policy query is only available on Windows")
}

/// Set Filtering Platform Connection auditing to an explicit state — used
/// both to enable collection and to restore the pre-firebreak state.
/// Note: local audit policy can be overridden by GPO on the next policy
/// refresh — if this flips back off between runs, that's the place to look.
pub fn set_auditing(state: AuditState) -> Result<()> {
    let onoff = |b: bool| if b { "enable" } else { "disable" };
    let out = crate::syspath::command(crate::syspath::system32_tool("auditpol.exe"))
        .args([
            "/set",
            &format!("/subcategory:{}", FILTERING_PLATFORM_CONNECTION_GUID),
            &format!("/success:{}", onoff(state.success)),
            &format!("/failure:{}", onoff(state.failure)),
        ])
        .output()
        .context("running auditpol.exe")?;
    if !out.status.success() {
        bail!(
            "auditpol /set failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

pub fn enable_auditing() -> Result<()> {
    set_auditing(AuditState {
        success: true,
        failure: true,
    })
}

/// Current max size of the Security log in bytes, via wevtutil gl.
pub fn security_log_max_bytes() -> Result<u64> {
    let out = crate::syspath::command(crate::syspath::system32_tool("wevtutil.exe"))
        .args(["gl", "Security"])
        .output()
        .context("running wevtutil gl Security")?;
    if !out.status.success() {
        bail!("wevtutil gl failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("maxSize:") {
            return rest.trim().parse::<u64>().context("parsing maxSize");
        }
    }
    bail!("maxSize not found in wevtutil output");
}

/// Set the Security log max size (bytes).
pub fn set_security_log_max_bytes(bytes: u64) -> Result<()> {
    let out = crate::syspath::command(crate::syspath::system32_tool("wevtutil.exe"))
        .args(["sl", "Security", &format!("/ms:{}", bytes)])
        .output()
        .context("running wevtutil sl Security")?;
    if !out.status.success() {
        bail!(
            "wevtutil sl failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Default target: 512 MiB. At a few hundred bytes per 5156 event this holds
/// on the order of a million-plus connections — tune upward for busy hosts
/// or long gaps between runs.
pub const DEFAULT_SECURITY_LOG_BYTES: u64 = 512 * 1024 * 1024;
