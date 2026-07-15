# firebreak — Windows Firewall rule-usage auditor

On-demand tool (no service, no driver) that answers: **which firewall rules
are actually being matched, by which applications, and how often** — so
unused rules can be disabled and used-but-broad rules can be security-vetted.

It works by correlating Windows' own WFP audit events (Security log 5156
allowed / 5157 blocked, which carry the application path and the WFP Filter
Run-Time ID) against the live WFP filter table and `Get-NetFirewallRule`.
See `ARCHITECTURE.md` for the full design and rationale.

## Build

Native on Windows: `cargo build --release`
Cross from Linux: `cargo build --release --target x86_64-pc-windows-gnu`
(needs `mingw64-gcc` and the rustup target).

## Run

Run **elevated**. Modes are auto-detected:

1. **First run (auditing off):** enables the "Filtering Platform Connection"
   audit subcategory (success+failure), grows the Security log to 512 MiB if
   smaller, snapshots the current rule set, and starts the collection clock.
   There is no retroactive data — run this as early as possible, then come
   back days/weeks later. Use `--enable-only` to do just this and exit.
2. **Auditing already on, first run of the tool:** ingests whatever history
   the Security log still holds.
3. **Normal run:** ingests events since the last checkpoint, aggregates
   per-rule usage into `%ProgramData%\firebreak\firebreak.db`, and opens the UI.

Flags: `--enable-only`, `--no-ui` (text report), `--dump-filters`
(diagnostics, see below), `--db <path>`.

The UI lists every rule with allow/block hit counts, last-seen time, the
applications observed hitting it (friendly names from PE version info), and
static baseline flags (mDNS/SSDP/LLMNR/RDP/SMB/broad-allow…). Checkboxes set
the intended enabled-state; **Apply** first writes a full policy backup to
`%ProgramData%\firebreak\backups\firewall-<stamp>.wfw` (restore with
`netsh advfirewall import <file>`) plus a JSON rule dump, then commits via
`Set-NetFirewallRule`.

## Interpreting results

- **Zero-hit enabled rules** are disable candidates — but only after the
  collection window has covered weekly/monthly-cadence activity (backup
  agents, license checks). Check "Collecting since" in the header.
- **Unattributed events** are normal in moderation: WFP has built-in/default
  filters that aren't firewall rules, and events recorded during a previous
  boot session reference filter IDs that no longer exist (filter run-time
  IDs regenerate at boot). The tool persists filter→rule mappings per run to
  partially cover past boots — running it at least once per boot session
  keeps attribution tight.
- Local audit policy can be reverted by **Group Policy** refresh. If event
  ingestion drops to zero unexpectedly:
  `auditpol /get /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}`

## Verification checklist (built blind — confirm on a real box)

This was written without access to a Windows host. Functionally everything
compiles and the event parser has test coverage, but the following are from
documentation/memory and are the first things to verify; all are cheap to
adjust:

1. **Filter→rule mapping (the load-bearing one).** Run `firebreak
   --dump-filters`, take a `FilterRTID` from a real 5156 event (Event
   Viewer → Security), and check what the matching filter's
   `provider_data_utf16` actually contains. Matching currently tries
   (a) providerData containing the rule's unique Name/InstanceID, then
   (b) filter display-name == rule DisplayName (only when unambiguous).
   If providerData turns out to hold something else, adjust
   `build_filter_rule_map` in `src/filter_map.rs`.
2. **Direction tokens**: `%%14592`=Inbound / `%%14593`=Outbound assumed
   (`decode_direction` in `src/event_query.rs`). Unrecognized tokens pass
   through raw, so a mistake is visible, not silent.
3. **auditpol by GUID**: `auditpol /set
   /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /success:enable
   /failure:enable` — GUID form used to dodge localized names; confirm the
   braces/quoting survive as-is.
4. **wevtutil maxSize parsing** (`security_log_max_bytes`): expects a
   `maxSize: <n>` line from `wevtutil gl Security`.
5. **PowerShell JSON shape** (`enumerate_rules`): `Get-NetFirewallRule`
   joined with `-All` application/port filters by InstanceID; check the
   port/program columns populate for a few known rules.
6. **First run end-to-end**: enable → generate traffic (browse somewhere) →
   rerun → the browser's rule shows hits with the right app name.

## What this tool deliberately is not

- Not a packet-capture or WFP callout driver — Windows already records
  everything needed; this only reads it.
- Not per-packet accounting: "Filtering Platform Connection" auditing is
  per-connection/flow. The per-packet subcategory ("Filtering Platform
  Packet Drop", {0CCE9225-…}) is intentionally never enabled.
