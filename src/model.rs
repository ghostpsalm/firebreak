use serde::{Deserialize, Serialize};

/// A firewall rule as enumerated via PowerShell (Get-NetFirewallRule joined
/// with its application/port filters). `name` is the InstanceID-style unique
/// name; `display_name` is what the GUI shows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "DisplayName")]
    pub display_name: String,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
    #[serde(rename = "Enabled")]
    pub enabled: String,
    #[serde(rename = "Direction")]
    pub direction: String,
    #[serde(rename = "Action")]
    pub action: String,
    #[serde(rename = "Profile")]
    pub profile: String,
    #[serde(rename = "Group", default)]
    pub group: Option<String>,
    #[serde(rename = "Program", default)]
    pub program: Option<String>,
    #[serde(rename = "Protocol", default)]
    pub protocol: Option<String>,
    #[serde(rename = "LocalPort", default)]
    pub local_port: Option<String>,
    #[serde(rename = "RemotePort", default)]
    pub remote_port: Option<String>,
}

impl RuleInfo {
    pub fn is_enabled(&self) -> bool {
        self.enabled.eq_ignore_ascii_case("true")
    }
}

/// One parsed 5156/5157 event. Several fields aren't consumed by the
/// aggregation yet but are parsed for future per-connection detail views.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EventRecord {
    pub event_id: u32,
    /// EventRecordID: monotonic per-channel cursor, the ingestion checkpoint
    pub record_id: u64,
    /// ISO8601 UTC
    pub time_created: String,
    pub filter_rtid: u64,
    /// Raw application path as logged (\device\harddiskvolumeN\... form)
    pub application: String,
    /// "Inbound" / "Outbound" / raw token if unrecognized
    pub direction: String,
    pub protocol: u32,
    pub dest_address: String,
    pub dest_port: String,
    pub source_address: String,
    pub source_port: String,
}

impl EventRecord {
    pub fn is_allow(&self) -> bool {
        self.event_id == 5156
    }
}

/// One WFP filter from FwpmFilterEnum0, with everything potentially useful
/// for mapping back to a firewall rule.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FilterInfo {
    pub filter_id: u64,
    pub name: String,
    pub description: String,
    /// providerData blob decoded as UTF-16LE (lossy); for MPSSVC firewall
    /// filters this is expected to carry the rule identity — verify on a
    /// real box with --dump-filters.
    pub provider_data_utf16: String,
    /// providerData blob as hex, for diagnosis when UTF-16 decode is garbage
    pub provider_data_hex: String,
    pub provider_context_key: String,
    pub layer_key: String,
}

/// Aggregated usage for one rule (or one unmatched filter), as read back
/// from the store for reporting.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct RuleUsage {
    pub rule_id: String,
    pub allow_count: i64,
    pub block_count: i64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    /// distinct application paths seen hitting this rule, with per-app hits
    pub apps: Vec<(String, i64)>,
}

/// A static baseline advisory attached to a rule by pattern matching.
#[derive(Debug, Clone)]
pub struct BaselineFlag {
    pub title: &'static str,
    pub advice: &'static str,
}
