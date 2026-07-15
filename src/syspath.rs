//! Absolute paths for the system executables we spawn. An elevated process
//! must not resolve tool names through the PATH/CreateProcess search order —
//! a planted powershell.exe next to the binary or in a user-writable PATH
//! entry would run with admin rights.

use std::path::PathBuf;

/// %SystemRoot%, set by the session manager, not user-writable when elevated.
fn system_root() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
}

/// Full path to a System32 tool, e.g. netsh.exe / auditpol.exe / wevtutil.exe.
pub fn system32_tool(exe_name: &str) -> PathBuf {
    system_root().join("System32").join(exe_name)
}

/// Windows PowerShell lives outside System32 proper.
pub fn powershell() -> PathBuf {
    system_root().join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
}
