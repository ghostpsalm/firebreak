//! Enumerate live WFP filters (FwpmFilterEnum0) and map filter run-time IDs
//! back to Windows Firewall rules.
//!
//! For filters created by the Windows Firewall service (MPSSVC), the
//! filter's display name matches the rule's DisplayName, and the
//! providerData blob is expected to carry the rule's identity. Exactly what
//! providerData contains needs verification on a real box (--dump-filters
//! exists for that); matching therefore tries, in order:
//!   1. providerData UTF-16 text containing a rule Name (InstanceID)
//!   2. filter display name == rule DisplayName (ambiguous if duplicated)

use anyhow::{bail, Result};
use std::collections::HashMap;

use crate::model::{FilterInfo, RuleInfo};

#[cfg(windows)]
pub fn enumerate_filters() -> Result<Vec<FilterInfo>> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterCreateEnumHandle0,
        FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FWPM_FILTER0,
    };

    const RPC_C_AUTHN_WINNT: u32 = 10;

    unsafe fn pwstr_to_string(p: windows::core::PWSTR) -> String {
        if p.is_null() {
            String::new()
        } else {
            p.to_string().unwrap_or_default()
        }
    }

    unsafe {
        let mut engine = HANDLE::default();
        let err = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
        if err != 0 {
            bail!("FwpmEngineOpen0 failed with error {err} (needs elevation)");
        }

        let result = (|| -> Result<Vec<FilterInfo>> {
            let mut enum_handle = HANDLE::default();
            let err = FwpmFilterCreateEnumHandle0(engine, None, &mut enum_handle);
            if err != 0 {
                bail!("FwpmFilterCreateEnumHandle0 failed with error {err}");
            }

            let mut out = Vec::new();
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                let mut returned: u32 = 0;
                let err = FwpmFilterEnum0(engine, enum_handle, 512, &mut entries, &mut returned);
                if err != 0 {
                    let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
                    bail!("FwpmFilterEnum0 failed with error {err}");
                }
                if returned == 0 {
                    if !entries.is_null() {
                        FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void);
                    }
                    break;
                }
                for i in 0..returned as usize {
                    let f = &**entries.add(i);
                    let provider_data =
                        std::slice::from_raw_parts(f.providerData.data, f.providerData.size as usize);
                    let (pd_utf16, pd_hex) = decode_provider_data(provider_data);
                    out.push(FilterInfo {
                        filter_id: f.filterId,
                        name: pwstr_to_string(f.displayData.name),
                        description: pwstr_to_string(f.displayData.description),
                        provider_data_utf16: pd_utf16,
                        provider_data_hex: pd_hex,
                        provider_context_key: format!("{:?}", f.Anonymous.providerContextKey),
                        layer_key: format!("{:?}", f.layerKey),
                    });
                }
                FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut core::ffi::c_void);
            }
            let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
            Ok(out)
        })();

        let _ = FwpmEngineClose0(engine);
        result
    }
}

#[cfg(not(windows))]
pub fn enumerate_filters() -> Result<Vec<FilterInfo>> {
    bail!("WFP filter enumeration is only available on Windows")
}

/// Decode a providerData blob as UTF-16LE text (lossy, control chars
/// stripped) plus a hex dump capped for storage.
fn decode_provider_data(data: &[u8]) -> (String, String) {
    let utf16: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text: String = String::from_utf16_lossy(&utf16)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let hex: String = data
        .iter()
        .take(256)
        .map(|b| format!("{b:02x}"))
        .collect();
    (text, hex)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedVia {
    ProviderData,
    DisplayName,
    #[allow(dead_code)]
    Historical,
    Unmatched,
}

impl MappedVia {
    pub fn as_str(&self) -> &'static str {
        match self {
            MappedVia::ProviderData => "provider_data",
            MappedVia::DisplayName => "display_name",
            MappedVia::Historical => "historical",
            MappedVia::Unmatched => "unmatched",
        }
    }
}

/// Build filter_id -> (rule Name, how it was matched). Rules whose
/// DisplayName is shared by several rules only match via providerData.
pub fn build_filter_rule_map(
    filters: &[FilterInfo],
    rules: &[RuleInfo],
) -> HashMap<u64, (String, MappedVia)> {
    // display name -> rule name, only when unambiguous
    let mut by_display: HashMap<&str, Option<&str>> = HashMap::new();
    for r in rules {
        by_display
            .entry(r.display_name.as_str())
            .and_modify(|v| *v = None) // duplicate display name: ambiguous
            .or_insert(Some(r.name.as_str()));
    }

    let mut map = HashMap::new();
    for f in filters {
        // 1. providerData carrying the rule Name (InstanceID) verbatim
        let mut matched: Option<(String, MappedVia)> = None;
        if !f.provider_data_utf16.is_empty() {
            for r in rules {
                if f.provider_data_utf16.contains(r.name.as_str()) {
                    matched = Some((r.name.clone(), MappedVia::ProviderData));
                    break;
                }
            }
        }
        // 2. unambiguous display-name match
        if matched.is_none() && !f.name.is_empty() {
            if let Some(Some(rule_name)) = by_display.get(f.name.as_str()) {
                matched = Some((rule_name.to_string(), MappedVia::DisplayName));
            }
        }
        if let Some(m) = matched {
            map.insert(f.filter_id, m);
        }
    }
    map
}
