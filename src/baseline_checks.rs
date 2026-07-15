//! Static advisory layer, independent of usage data. These are prompts for
//! review, not verdicts — several of these protocols are load-bearing on
//! networks that use AirPlay/Chromecast/network printers/etc. The list
//! should be reconciled against a current Microsoft Security Compliance
//! Toolkit / CIS benchmark before being treated as authoritative.

use crate::model::{BaselineFlag, RuleInfo};

struct Check {
    /// substrings matched case-insensitively against DisplayName or Group
    name_hints: &'static [&'static str],
    /// (protocol, local port) match as fallback when names don't hit
    port_hint: Option<(&'static str, &'static str)>,
    inbound_only: bool,
    flag: BaselineFlag,
}

const CHECKS: &[Check] = &[
    Check {
        name_hints: &["mdns"],
        port_hint: Some(("UDP", "5353")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "mDNS",
            advice: "Multicast discovery (AirPlay/Chromecast/printers). Commonly disabled on hardened/domain profiles; keep if local device discovery is needed.",
        },
    },
    Check {
        name_hints: &["ssdp"],
        port_hint: Some(("UDP", "1900")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "SSDP/UPnP",
            advice: "UPnP discovery. Frequent hardening target; disable unless UPnP device discovery is actually used.",
        },
    },
    Check {
        name_hints: &["llmnr", "link-local multicast"],
        port_hint: Some(("UDP", "5355")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "LLMNR",
            advice: "Legacy name resolution, credential-relay attack surface. Microsoft/CIS baselines recommend disabling (also via GPO, not just firewall).",
        },
    },
    Check {
        name_hints: &["netbios", "nb-"],
        port_hint: Some(("UDP", "137")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "NetBIOS",
            advice: "Legacy name service (137-139). Disable unless legacy SMB/browsing on the LAN requires it.",
        },
    },
    Check {
        name_hints: &["wsd", "ws-discovery", "function discovery"],
        port_hint: Some(("UDP", "3702")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "WS-Discovery",
            advice: "Device discovery (printers/scanners). Review on anything not needing plug-and-play network devices.",
        },
    },
    Check {
        name_hints: &["remote desktop", "rdp"],
        port_hint: Some(("TCP", "3389")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "RDP",
            advice: "Remote Desktop inbound. If used, restrict RemoteAddress scope; if unused, disable — top lateral-movement target.",
        },
    },
    Check {
        name_hints: &["file and printer sharing (smb"],
        port_hint: Some(("TCP", "445")),
        inbound_only: true,
        flag: BaselineFlag {
            title: "SMB inbound",
            advice: "Inbound file sharing. Workstations rarely need to *serve* SMB; disable inbound 445 unless this host shares files/printers.",
        },
    },
    Check {
        name_hints: &["remote assistance"],
        port_hint: None,
        inbound_only: true,
        flag: BaselineFlag {
            title: "Remote Assistance",
            advice: "Commonly disabled by baseline unless the org actively uses solicited Remote Assistance.",
        },
    },
];

pub fn flags_for(rule: &RuleInfo) -> Vec<BaselineFlag> {
    let mut out = Vec::new();
    let name = rule.display_name.to_lowercase();
    let group = rule.group.as_deref().unwrap_or("").to_lowercase();
    let inbound = rule.direction.eq_ignore_ascii_case("inbound");

    for check in CHECKS {
        if check.inbound_only && !inbound {
            continue;
        }
        let name_hit = check
            .name_hints
            .iter()
            .any(|h| name.contains(h) || group.contains(h));
        let port_hit = match (&check.port_hint, &rule.protocol, &rule.local_port) {
            (Some((proto, port)), Some(rp), Some(rport)) => {
                rp.eq_ignore_ascii_case(proto) && rport.split(',').any(|p| p == *port)
            }
            _ => false,
        };
        if name_hit || port_hit {
            out.push(check.flag.clone());
        }
    }

    // structural check: enabled Allow rule with no program and no port
    // restriction is maximally broad
    if rule.is_enabled()
        && rule.action.eq_ignore_ascii_case("allow")
        && rule.program.as_deref().map_or(true, |p| p.is_empty() || p == "Any")
        && rule.local_port.as_deref().map_or(true, |p| p.is_empty() || p == "Any")
        && inbound
    {
        out.push(BaselineFlag {
            title: "Broad inbound allow",
            advice: "Inbound allow with no program and no port restriction — vet scope (RemoteAddress, profile) or tighten.",
        });
    }
    out
}
