//! Self-update via GitHub Releases.
//!
//! HTTP goes through PowerShell (like every other subprocess in the app) so we
//! inherit the OS TLS stack and add no networking crates. The download always
//! comes from the stable "latest" URL, so a single link persists across
//! versions; the API is only consulted to learn the newest tag for comparison.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

/// `owner/repo` hosting the releases. Local-only today — set this to the real
/// repository when firebreak is published. Until a reachable release exists the
/// update UI degrades gracefully (it reports that it couldn't reach updates).
pub const REPO: &str = "ghostpsalm/firebreak";

/// Asset uploaded to each release.
pub const ASSET: &str = "firebreak.exe";

/// The single persistent download link — always resolves to the newest asset.
pub fn download_url() -> String {
    format!("https://github.com/{REPO}/releases/latest/download/{ASSET}")
}

#[derive(Clone)]
pub struct Release {
    /// Newest published version, normalized to `major.minor.patch.build`.
    pub latest: String,
    /// The running build's version string.
    pub current: String,
    /// True when `latest` is strictly newer than `current`.
    pub newer: bool,
}

/// Ask GitHub for the latest release tag and compare it to the running build.
pub fn check() -> Result<Release> {
    let api = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; \
         (Invoke-RestMethod -UseBasicParsing -Uri '{api}' \
           -Headers @{{'User-Agent'='firebreak';'Accept'='application/vnd.github+json'}}).tag_name"
    );
    let out = crate::syspath::command(crate::syspath::powershell())
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .context("launching PowerShell for the update check")?;
    if !out.status.success() {
        return Err(anyhow!(
            "couldn't reach updates: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let tag = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if tag.is_empty() {
        return Err(anyhow!("no release published yet"));
    }
    let latest = normalize(&tag);
    let current = crate::pipeline::version_string();
    let newer = is_newer(&latest, &current);
    Ok(Release { latest, current, newer })
}

/// Download the latest asset and swap it in next to the running exe. On success
/// the running image has been moved to `<name>.old` and the new build sits in
/// its place; the caller then prompts a restart. Returns the path to relaunch.
pub fn download_and_install() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locating the running exe")?;
    let dir = exe.parent().ok_or_else(|| anyhow!("running exe has no parent directory"))?;
    let new = dir.join(format!("{ASSET}.new"));
    let old = dir.join(format!("{ASSET}.old"));

    let url = download_url();
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; \
         Invoke-WebRequest -UseBasicParsing -Uri '{url}' -OutFile '{}'",
        new.display()
    );
    let out = crate::syspath::command(crate::syspath::powershell())
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .context("launching PowerShell for the download")?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&new);
        return Err(anyhow!(
            "download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let size = std::fs::metadata(&new).map(|m| m.len()).unwrap_or(0);
    if size < 1024 {
        let _ = std::fs::remove_file(&new);
        return Err(anyhow!("the downloaded file looks incomplete ({size} bytes)"));
    }

    // Windows lets us rename a running exe but not overwrite it: move the
    // running image aside, then swap the new build into its place.
    let _ = std::fs::remove_file(&old);
    std::fs::rename(&exe, &old).context("moving the running exe aside")?;
    if let Err(e) = std::fs::rename(&new, &exe) {
        let _ = std::fs::rename(&old, &exe); // roll back so the app still exists on disk
        return Err(anyhow::Error::new(e).context("installing the new exe"));
    }
    Ok(exe)
}

/// Relaunch the freshly installed exe and exit this process.
pub fn restart(exe: &Path) -> ! {
    let _ = crate::syspath::command(exe).spawn();
    std::process::exit(0);
}

/// Best-effort cleanup of a leftover `.old` from a previous update. Call once at
/// startup, after the OS has released the old image.
pub fn cleanup_old() {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let _ = std::fs::remove_file(dir.join(format!("{ASSET}.old")));
        }
    }
}

fn normalize(tag: &str) -> String {
    tag.trim().trim_start_matches(['v', 'V']).to_string()
}

/// Numeric dotted-version comparison; missing trailing components count as 0.
fn is_newer(latest: &str, current: &str) -> bool {
    let parse = |s: &str| s.split('.').map(|p| p.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    let (a, b) = (parse(latest), parse(current));
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_v_prefix() {
        assert_eq!(normalize("v0.5.4.1200"), "0.5.4.1200");
        assert_eq!(normalize("0.5.4"), "0.5.4");
    }

    #[test]
    fn newer_by_component() {
        assert!(is_newer("0.5.4.10", "0.5.3.999"));
        assert!(is_newer("0.5.3.1001", "0.5.3.1000"));
        assert!(is_newer("1.0.0.0", "0.9.9.9"));
    }

    #[test]
    fn not_newer_when_equal_or_older() {
        assert!(!is_newer("0.5.3.1000", "0.5.3.1000"));
        assert!(!is_newer("0.5.3", "0.5.3.0"));
        assert!(!is_newer("0.5.2.5000", "0.5.3.1"));
    }
}
