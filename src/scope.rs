//! Scope-based attribution: which firewall rules' criteria a given
//! connection satisfies. Windows' FilterOrigin names the *decisive* filter,
//! which for allowed traffic is frequently a system default (e.g. mDNS on
//! UDP 5353 is admitted by an interface pre-filter, FilterOrigin
//! "Unknown"), never the user's mDNS rule. For a usage audit the question
//! is "did traffic matching this rule's scope occur?" — so we credit every
//! enabled/relevant rule whose direction + protocol + local/remote port +
//! program the connection matches. One connection can credit several rules
//! (overlapping scopes); that is correct — each is "exercised".

use std::collections::{HashMap, HashSet};

use crate::listeners::parse_port_ranges;
use crate::model::{EventRecord, RuleInfo};

/// IANA protocol numbers as they appear in 5156/5157 events.
fn proto_to_num(s: &str) -> Option<u32> {
    match s.trim().to_ascii_uppercase().as_str() {
        "ICMPV4" | "ICMP" => Some(1),
        "IGMP" => Some(2),
        "TCP" => Some(6),
        "UDP" => Some(17),
        "IPV6-ICMP" | "ICMPV6" => Some(58),
        other => other.parse().ok(),
    }
}

fn basename(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Expand the couple of env-var forms Windows rules use in Program paths,
/// enough for basename comparison.
fn expand_program(p: &str) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    p.replace("%SystemRoot%", &root)
        .replace("%systemroot%", &root)
        .replace("%windir%", &root)
}

fn in_ranges(port: u32, ranges: &[(u32, u32)]) -> bool {
    ranges.iter().any(|&(a, b)| port >= a && port <= b)
}

/// One rule's match criteria. `None` on a field means "Any" (unconstrained).
struct RuleScope {
    rule_name: String,
    dir_in: bool,
    protocols: Option<HashSet<u32>>,
    local_ports: Option<Vec<(u32, u32)>>,
    remote_ports: Option<Vec<(u32, u32)>>,
    program_base: Option<String>,
}

impl RuleScope {
    fn from_rule(r: &RuleInfo) -> Option<RuleScope> {
        let dir_in = if r.direction.eq_ignore_ascii_case("inbound") {
            true
        } else if r.direction.eq_ignore_ascii_case("outbound") {
            false
        } else {
            return None;
        };
        let protocols = match r.protocol.as_deref() {
            Some(p) if !p.is_empty() && !p.eq_ignore_ascii_case("any") => {
                let set: HashSet<u32> = p.split(',').filter_map(proto_to_num).collect();
                (!set.is_empty()).then_some(set)
            }
            _ => None,
        };
        let ports = |spec: Option<&str>| -> Option<Vec<(u32, u32)>> {
            spec.map(str::trim)
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("any"))
                .map(parse_port_ranges)
        };
        let program_base = r
            .program
            .as_deref()
            .filter(|p| !p.is_empty() && !p.eq_ignore_ascii_case("any"))
            .map(|p| basename(&expand_program(p)).to_lowercase());
        Some(RuleScope {
            rule_name: r.name.clone(),
            dir_in,
            protocols,
            local_ports: ports(r.local_port.as_deref()),
            remote_ports: ports(r.remote_port.as_deref()),
            program_base,
        })
    }

    fn matches(&self, c: &Conn) -> bool {
        if self.dir_in != c.dir_in {
            return false;
        }
        if let Some(ps) = &self.protocols {
            if !ps.contains(&c.proto) {
                return false;
            }
        }
        // a symbolic/unresolved port spec parses to an empty range list —
        // treat as "cannot confirm", i.e. don't match on ports alone
        if let Some(lp) = &self.local_ports {
            if lp.is_empty() || !in_ranges(c.local_port, lp) {
                return false;
            }
        }
        if let Some(rp) = &self.remote_ports {
            if rp.is_empty() || !in_ranges(c.remote_port, rp) {
                return false;
            }
        }
        if let Some(pb) = &self.program_base {
            if c.app_base.is_empty() || &c.app_base != pb {
                return false;
            }
        }
        true
    }
}

/// A connection reduced to its match-relevant fields.
pub struct Conn {
    pub dir_in: bool,
    pub proto: u32,
    pub local_port: u32,
    pub remote_port: u32,
    pub app_base: String,
}

impl Conn {
    /// Build from an event. Local endpoint = dest for inbound, source for
    /// outbound; remote is the other side.
    pub fn from_event(ev: &EventRecord, normalized_app: &str) -> Conn {
        let dir_in = ev.direction.eq_ignore_ascii_case("inbound");
        let dp: u32 = ev.dest_port.trim().parse().unwrap_or(0);
        let sp: u32 = ev.source_port.trim().parse().unwrap_or(0);
        let (local_port, remote_port) = if dir_in { (dp, sp) } else { (sp, dp) };
        Conn {
            dir_in,
            proto: ev.protocol,
            local_port,
            remote_port,
            app_base: basename(normalized_app).to_lowercase(),
        }
    }
}

/// Rule scopes indexed by (direction, protocol) for fast candidate lookup.
pub struct ScopeIndex {
    scopes: Vec<RuleScope>,
    // direction -> protocol -> rule indices; plus per-direction any-protocol
    by_proto: HashMap<(bool, u32), Vec<usize>>,
    any_proto: HashMap<bool, Vec<usize>>,
}

impl ScopeIndex {
    pub fn build(rules: &[RuleInfo]) -> ScopeIndex {
        let mut scopes = Vec::new();
        let mut by_proto: HashMap<(bool, u32), Vec<usize>> = HashMap::new();
        let mut any_proto: HashMap<bool, Vec<usize>> = HashMap::new();
        for r in rules {
            if let Some(s) = RuleScope::from_rule(r) {
                let idx = scopes.len();
                match &s.protocols {
                    Some(ps) => {
                        for &p in ps {
                            by_proto.entry((s.dir_in, p)).or_default().push(idx);
                        }
                    }
                    None => any_proto.entry(s.dir_in).or_default().push(idx),
                }
                scopes.push(s);
            }
        }
        ScopeIndex { scopes, by_proto, any_proto }
    }

    /// Names of all rules whose scope this connection matches.
    pub fn matching_rules(&self, c: &Conn) -> Vec<&str> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let candidates = self
            .by_proto
            .get(&(c.dir_in, c.proto))
            .into_iter()
            .flatten()
            .chain(self.any_proto.get(&c.dir_in).into_iter().flatten());
        for &idx in candidates {
            if seen.insert(idx) && self.scopes[idx].matches(c) {
                out.push(self.scopes[idx].rule_name.as_str());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, dir: &str, proto: Option<&str>, lport: Option<&str>, rport: Option<&str>, prog: Option<&str>) -> RuleInfo {
        RuleInfo {
            name: name.into(),
            display_name: name.into(),
            description: None,
            enabled: "True".into(),
            direction: dir.into(),
            action: "Allow".into(),
            profile: "Any".into(),
            group: None,
            program: prog.map(Into::into),
            protocol: proto.map(Into::into),
            local_port: lport.map(Into::into),
            remote_port: rport.map(Into::into),
            service: None,
            remote_address: None,
        }
    }

    fn ev(dir: &str, proto: u32, sp: &str, dp: &str, app: &str) -> EventRecord {
        EventRecord {
            event_id: 5156,
            record_id: 1,
            time_created: "t".into(),
            filter_rtid: 0,
            application: app.into(),
            direction: dir.into(),
            filter_origin: Some("Unknown".into()),
            protocol: proto,
            dest_address: "d".into(),
            dest_port: dp.into(),
            source_address: "s".into(),
            source_port: sp.into(),
        }
    }

    #[test]
    fn mdns_inbound_credits_the_5353_rule() {
        // the exact case from the field: UDP 5353 inbound, FilterOrigin Unknown
        let rules = vec![
            rule("mDNS", "Inbound", Some("UDP"), Some("5353"), None, None),
            rule("RDP", "Inbound", Some("TCP"), Some("3389"), None, None),
        ];
        let idx = ScopeIndex::build(&rules);
        let e = ev("Inbound", 17, "5353", "5353", r"\device\hd\svchost.exe");
        let c = Conn::from_event(&e, r"C:\windows\system32\svchost.exe");
        assert_eq!(idx.matching_rules(&c), vec!["mDNS"]);
    }

    #[test]
    fn icmp_ping_credits_protocol_only_rule() {
        let rules = vec![rule("Echo Request v4", "Inbound", Some("ICMPv4"), None, None, None)];
        let idx = ScopeIndex::build(&rules);
        let e = ev("Inbound", 1, "0", "0", "System");
        let c = Conn::from_event(&e, "System");
        assert_eq!(idx.matching_rules(&c), vec!["Echo Request v4"]);
    }

    #[test]
    fn program_and_port_both_required() {
        let rules = vec![rule("svc5000", "Inbound", Some("TCP"), Some("5000-5020"), None, Some(r"C:\x\svchost.exe"))];
        let idx = ScopeIndex::build(&rules);
        // right program, wrong port
        let miss = Conn::from_event(&ev("Inbound", 6, "40000", "135", "svchost.exe"), r"C:\x\svchost.exe");
        assert!(idx.matching_rules(&miss).is_empty());
        // right program and port
        let hit = Conn::from_event(&ev("Inbound", 6, "40000", "5010", "svchost.exe"), r"C:\x\svchost.exe");
        assert_eq!(idx.matching_rules(&hit), vec!["svc5000"]);
    }

    #[test]
    fn outbound_matches_on_remote_port() {
        let rules = vec![rule("DNS out", "Outbound", Some("UDP"), None, Some("53"), None)];
        let idx = ScopeIndex::build(&rules);
        // outbound: local=source(ephemeral), remote=dest(53)
        let c = Conn::from_event(&ev("Outbound", 17, "50000", "53", "svchost.exe"), "svchost.exe");
        assert_eq!(idx.matching_rules(&c), vec!["DNS out"]);
    }

    #[test]
    fn direction_and_protocol_gate() {
        let rules = vec![rule("mDNS in", "Inbound", Some("UDP"), Some("5353"), None, None)];
        let idx = ScopeIndex::build(&rules);
        // outbound UDP 5353 must not match an inbound rule
        let c = Conn::from_event(&ev("Outbound", 17, "5353", "5353", "svchost.exe"), "svchost.exe");
        assert!(idx.matching_rules(&c).is_empty());
        // TCP 5353 must not match a UDP rule
        let c2 = Conn::from_event(&ev("Inbound", 6, "5353", "5353", "svchost.exe"), "svchost.exe");
        assert!(idx.matching_rules(&c2).is_empty());
    }
}
