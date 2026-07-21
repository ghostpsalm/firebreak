# Deep Code Review — Firebreak — 2026-07-21

Scope: full repository (`/home/kogies/win-firewall`, branch `main`, commit `603d17e`). Focus areas requested: security, code cleanliness/efficiency, performance optimization, and — specifically — **accuracy of firewall rule counting/matching** (do the displayed counts exactly reflect real firewall rules and real traffic, not approximations).

## 1. Executive summary

Firebreak is a small (~9,800 LOC), well-structured Rust/egui Windows tool that correlates WFP Security-log audit events (5156/5157) against enumerated firewall rules to surface unused/over-broad rules. The codebase is unusually disciplined for its size: parameterized SQL everywhere, hardened data directories, absolute subprocess paths (no PATH-hijack surface), PowerShell-injection-safe argument construction, a sound single-transaction ingestion design, and 46 passing unit tests that specifically target prior regressions (there are code comments referencing at least two named past bugs, e.g. "C-04" and "the 30-identical-rows bug").

Against the requested accuracy focus: **the total rule count displayed ("N rules") is exact** — it is a 1:1 pass-through of `Get-NetFirewallRule`'s output with no filtering or deduplication anywhere in the path, confirmed by full read of `firewall_rules.rs`, `pipeline.rs::build_rows`, and `ui/paint.rs`'s header renderer. However, the **per-rule hit/usage attribution has a confirmed accuracy bug** (F1): disabled firewall rules can receive Allow/Block "hit" credit for traffic they never actually filtered, because the scope-matching engine never checks `rule.enabled` — directly contradicting its own doc comment. This is the most significant finding of the review and sits squarely inside the "match exactly, not nearly" ask.

Beyond that, one CLI-parsing correctness bug (F2), one narrow/unverifiable silent-data-loss risk in event parsing (F3), one cosmetic dead-field issue (F4), and one supply-chain hardening gap in the self-update flow (F5) were found. No SQL/command injection, no PATH hijacking, no TLS bypass, no unbounded resource exhaustion, and no concurrency-correctness bugs were found in five full passes plus one convergence sweep (a second sweep over P1 files and all prior-finding files yielded zero new Medium+ findings, so convergence was reached after 1 sweep, capped well under the 3-sweep budget).

**Findings: 1 High, 2 Medium, 2 Low (5 total: 4 Confirmed, 1 Suspected).** Production readiness: solid for its stated purpose once F1 is fixed — F1 undermines the specific "which rules are actually being matched" claim the tool exists to make. Nothing found is a security-critical injection/RCE-class bug in the traditional sense; F5 is a supply-chain hardening recommendation rather than an active exploit path.

| Severity | Count |
|---|---|
| High | 1 |
| Medium | 2 |
| Low | 2 |

## 2. Findings table

| ID | Pass | Severity | Status | Title | Location |
|---|---|---|---|---|---|
| F1 | Correctness/Accuracy | High | Confirmed | Disabled rules receive traffic credit they cannot have earned | src/scope.rs:90-256, src/pipeline.rs:515,238 |
| F5 | Security | Medium | Confirmed | Self-update installs an unverified binary with the tool's elevated trust | src/update.rs:93-116 |
| F2 | Correctness | Medium | Confirmed | `--collect` silently swallows the following CLI flag | src/main.rs:60-63 |
| F3 | Correctness/Accuracy | Low | Suspected | Events that fail to parse are silently and permanently skipped | src/event_query.rs:305-422 |
| F4 | Cleanliness | Low | Confirmed | `UnmatchedRow.filter_id`/`boot_session` are always empty (dead fields, misleading UI text) | src/pipeline.rs:404-410, src/ui/paint.rs:1997 |

## 3. Findings detail

### F1 — High — Confirmed — Disabled rules receive traffic credit they cannot have earned

**Location:** `src/scope.rs:90-139` (`RuleScope::from_rule`), `src/scope.rs:234-256` (`ScopeIndex::build`), `src/pipeline.rs:515` (`analyze`), `src/pipeline.rs:238` (`import_events`).

**The claim, and why it's a claim not evidence:** `scope.rs`'s module doc comment states the design intent explicitly:

> "For a usage audit the question is 'did traffic matching this rule's scope occur?' — so we credit every **enabled**/relevant rule whose direction + protocol + local/remote port + program the connection matches."

**Evidence the claim is false:** `RuleScope::from_rule` (scope.rs:90) builds a `RuleScope` from every field of `RuleInfo` except `enabled` — there is no `if !r.is_enabled() { return None }` guard, unlike the direction guard that *does* exist two lines later (`let dir_in = ... else { return None }`). `ScopeIndex::build` (scope.rs:234) iterates every rule passed to it with no enabled filter either. Both call sites that build the index — `pipeline::analyze` (line 515) and `pipeline::import_events` (line 238) — pass the complete, unfiltered result of `firewall_rules::enumerate_rules()` (or the bundle's `rules` field) straight in. Grep confirms `is_enabled`/`.enabled` appear nowhere in `scope.rs` or in the `ScopeIndex`-building call sites.

**Realistic failure scenario:** A host has two overlapping inbound TCP/3389 rules — the built-in enabled "Remote Desktop" rule, and a leftover/vendor-installed rule for the same port that has been disabled (a very common real-world state; RDP rules are frequently duplicated by different installers). A legitimate RDP connection arrives. WFP evaluates and admits it via the *enabled* rule only — the disabled rule is not loaded into the filter engine at all and cannot have participated in the decision. But `ScopeIndex::matching_rules` returns *both* rule names (their scopes both match direction+protocol+port), so `pipeline::analyze`'s ingestion loop (`for rule_name in matched { store.record_event(rule_name, ...) }`, pipeline.rs:554) calls `store.record_event` for the disabled rule too. The UI (`ui/paint.rs:1327`, "Hits A/B" column) then shows a non-zero Allow count, a "last seen" timestamp, and observed application names on a rule that is unambiguously **off**. This directly contradicts the tool's stated purpose ("which firewall rules are actually being matched") and can mislead the exact "disable zero-hit rules" workflow the tool exists to support — a disabled rule showing traffic looks "still relevant," and conversely a user auditing a *different*, similarly-scoped disabled rule with real zero traffic has no way to distinguish a trustworthy zero from a scope-index artifact once they've seen the tool misattribute once.

**Why the existing tests didn't catch it:** all seven `scope.rs` unit tests use a `rule()` test helper that hardcodes `enabled: "True".into()` — there is no test exercising a disabled rule through `ScopeIndex`/`matching_rules` at all, so the code path was structurally untested.

**Remediation:**
```rust
// scope.rs, in RuleScope::from_rule, alongside the existing direction guard:
fn from_rule(r: &RuleInfo) -> Option<RuleScope> {
    if !r.is_enabled() {
        return None; // a disabled rule is never loaded into WFP; it cannot be credited
    }
    let dir_in = if r.direction.eq_ignore_ascii_case("inbound") {
        true
    } else if r.direction.eq_ignore_ascii_case("outbound") {
        false
    } else {
        return None;
    };
    // ...
}
```
This is a one-line, low-risk fix consistent with the module's own documented intent. It affects only *future* ingestion (new events processed after the fix ships), consistent with the project's existing pattern of "current understanding governs new aggregation" (e.g. the "Reviewed" mark's fingerprint-staleness design already accepts that historical aggregates reflect the rule definition understood at ingest time). Add a regression test mirroring `unconstrained_rule_is_excluded` but for a disabled rule with an otherwise-matching scope, to close the gap that let this slip through.

---

### F5 — Medium — Confirmed — Self-update installs an unverified binary with the tool's elevated trust (CWE-494)

**Location:** `src/update.rs:93-150` (`download_and_install`, `download_to`), `src/winhttp.rs`.

Firebreak always runs elevated (embedded `requireAdministrator` manifest; `main.rs` re-checks and re-elevates if bypassed) and directly mutates Windows Firewall policy. Its self-update flow downloads `firebreak.exe` over HTTPS from a fixed `github.com/{owner}/{repo}/releases/latest/download/firebreak.exe` URL via WinHTTP (`WINHTTP_FLAG_SECURE`, default OS certificate validation — no `SECURITY_FLAG_IGNORE_*` bypass was found, so the TLS layer itself is sound), then renames the download directly over the running executable (`download_and_install`, update.rs:93). The only post-download check is `size < 1024` bytes — an "incomplete download" heuristic, not an authenticity check. There is no checksum, detached signature, or Authenticode verification before the new binary replaces the running one and is later launched via `update::restart()` with the same elevated context the update mechanism itself already had.

The README already documents that the shipped binary is unsigned ("Windows may warn on the unsigned binary — SmartScreen"), so there is no Authenticode chain a user or the OS can fall back on either. The entire trust chain for "this code should be allowed to run as Administrator on this machine" reduces to "the TLS certificate for github.com validated and the bytes came from the right URL path" — which is a reasonable baseline but doesn't protect against compromise of the GitHub release pipeline or the maintainer account, a class of incident that has happened to other real projects.

**Failure scenario:** an attacker who can publish an asset at that release URL (compromised maintainer credentials, a supply-chain compromise of the build/release pipeline, or a redirect-target compromise, since WinHTTP follows https→https redirects by design here) can ship a binary that every Firebreak install with a pending update will download and, on the next "Restart now" click, execute as Administrator.

**Remediation:** publish a detached signature (minisign or sigstore/cosign) or a `SHA256SUMS` file alongside each GitHub release and verify it against a key pinned in the binary before the `fs::rename` swap; or, more simply, Authenticode-sign `firebreak.exe` in CI and call `WinVerifyTrust` on the downloaded file before installing it, rejecting anything whose signature doesn't chain to the expected publisher. Either approach turns "trust TLS + GitHub" into "trust a specific, revocable signing key," which is the standard bar for an auto-updater with admin-level reach.

**Trade-off:** requires either a code-signing certificate (cost) or standing up a minisign/sigstore keypair and CI step (engineering time); worth doing before this ships broadly given what the tool already has permission to do.

---

### F2 — Medium — Confirmed — `--collect` silently swallows the following CLI flag

**Location:** `src/main.rs:60-63`.

```rust
"--collect" => {
    // optional path; default lands on the Desktop
    args.collect = Some(it.next().filter(|p| !p.starts_with("--")).map(Into::into));
}
```

`it.next()` unconditionally consumes the next token off the argument iterator to peek at it. When that token is actually the *next flag* (starts with `--`), `.filter()` discards it as a candidate path — correctly deciding "no path was given" — but the token itself has already been removed from `it` and there is no push-back; the outer `while let Some(a) = it.next()` loop simply never sees it again.

**Failure scenario:** `firebreak.exe --collect --enable-only` is meant to (per the tool's own `--help` text, which documents both flags as independent) export a bundle *and* separately enable auditing, or at minimum should either combine sensibly or reject the combination with an error. Instead it silently executes only `--collect` with the default output path; `--enable-only` vanishes with no error, warning, or exit code signal. Any user who scripts `firebreak.exe --collect [other-flag]` for automation will have `[other-flag]` silently ignored. A related but distinct issue exists for `--db`: `"--db" => match it.next() { Some(p) => args.db_path = p.into(), None => {...} }` takes the next token unconditionally with no `--`-prefix check, so `firebreak.exe --db --no-ui` sets `db_path` to the literal string `"--no-ui"` (which will then fail later with a confusing file-path error) and also loses `--no-ui` as a flag.

**Remediation:**
```rust
let mut it = std::env::args().skip(1).peekable();
...
"--collect" => {
    let path = it.peek().filter(|p| !p.starts_with("--")).cloned();
    if path.is_some() { it.next(); }
    args.collect = Some(path.map(Into::into));
}
"--db" => {
    match it.peek().filter(|p| !p.starts_with("--")) {
        Some(_) => args.db_path = it.next().unwrap().into(),
        None => { eprintln!("--db requires a path argument"); std::process::exit(2); }
    }
}
```
No existing test coverage exists for `parse_args` at all (main.rs has no `#[cfg(test)]` module); adding a couple of argv-vector unit tests around this function would catch regressions here going forward.

---

### F3 — Low — Suspected — Events that fail to parse are silently and permanently skipped

**Location:** `src/event_query.rs:305-422` (`parse_event_xml`), `src/event_query.rs:134-156` (`query_events`), `src/pipeline.rs:532-560` (`analyze`).

`parse_event_xml` requires a `FilterRTID` field to be present (`let filter_rtid = filter_rtid?;`, event_query.rs:403) and returns `None` — silently, with no counter or log line — if it's missing, or if the `EventID` isn't 5156/5157. `query_events`/`query_events_from_file` only invoke the `on_event` callback (and thus only advance `events_processed` and `max_record_id`) for events that parsed successfully (event_query.rs:147-153).

Because `pipeline::analyze` sets the next ingestion checkpoint to `max_record_id` — the highest **successfully-parsed** `EventRecordID` seen in the batch (pipeline.rs:534-536, :571-572) — and the resume XPath is a strict `EventRecordID > checkpoint` (event_query.rs:17-24, verified by test `query_uses_strictly_greater_integer_cursor`), any event that renders as XML but fails to parse (a record with a missing/malformed field, whether from log corruption or a Windows build variance the parser doesn't expect) is silently dropped **and never retried**, once a later, higher-numbered event has advanced the checkpoint past it. The existing "coverage gap" detector (`oldest_record_id()` vs. checkpoint, pipeline.rs:496-504) only catches log-rollover-style gaps, not this per-event parse-failure gap — so a user auditing "N events processed, 0 coverage gaps" has no signal that some events were silently excluded from every count in the tool.

**Why this is Suspected, not Confirmed:** `FilterRTID` is documented by Microsoft as a standard field on both 5156 and 5157, so on an uncorrupted, standard-schema Security log this should essentially never trigger. This review had no live Windows host available to construct a record that reproduces the drop (the skill's "prefer empirical over inferential" principle applies but couldn't be executed here — flagged honestly as a coverage gap rather than glossed over).

**Remediation:** track and surface a "N events could not be parsed" counter (mirroring `unmatched_events`), include it in the report/coverage-gap note, and consider whether such events should still advance the checkpoint (accepting the loss but not silently) versus block checkpoint advancement (retry forever, risking a stuck cursor on a persistently malformed record) — the latter needs a bound (e.g. skip-with-warning after N retries) to avoid the opposite failure mode.

---

### F4 — Low — Confirmed — `UnmatchedRow.filter_id`/`boot_session` are always empty (dead fields, misleading UI text)

**Location:** `src/pipeline.rs:396-412` (`build_unmatched`), `src/ui/paint.rs:1992-1999` (`unattributed_body`), `src/main.rs:283-306` (`print_text_report`).

`build_unmatched` always constructs `UnmatchedRow { filter_id: String::new(), boot_session: String::new(), filter_name: describe_origin(&label), usage }` (pipeline.rs:404-410) — vestigial fields from what the surrounding comments (store.rs's `filter_map` table doc, `filter_map.rs`'s module doc) show was an earlier, WFP-filter-ID-based attribution design that the current scope-based `analyze()` pipeline superseded. Confirmed vestigial by cross-reference: `preview.rs`'s mock-data fixture (`unmatched_row`, preview.rs:221-238) is the *only* place in the codebase that populates non-empty values for these two fields — the real pipeline never does.

The UI nonetheless renders them: `ui/paint.rs:1997` does `format!("filter {}", u.filter_id)`, which — given `filter_id` is always `""` — always displays the literal text `"filter "` (with a trailing space and no number) in the Unattributed events drawer. `main.rs:294`'s `--no-ui` text report has the equivalent `u.boot_session.get(..10).unwrap_or(&u.boot_session)` always evaluating to an empty string.

**Failure scenario:** purely cosmetic/confusing — a user reviewing the Unattributed panel or text report sees "filter " with nothing after it, which reads as a rendering bug even though it doesn't affect any count.

**Remediation:** remove the two dead fields from `UnmatchedRow` and the two display sites that reference them (simplest), or, if per-boot-session filter-ID granularity is still wanted for the Unattributed panel, wire them from the actual `default:<origin>` bucket data the current pipeline does track.

## 4. Claims Register

| ID | Location | Claim | Verdict | Evidence |
|---|---|---|---|---|
| C1 | scope.rs:8-9 | "we credit every **enabled**/relevant rule..." | **FALSE** | See F1. Elevated to a High finding since a false claim on the tool's core accuracy property is judged at the severity of its consequence, not the severity of the comment. |
| C2 | pipeline.rs:76-77 (README) | "Ingestion is a single transaction: a crash rolls back cleanly and the rerun cannot double-count." | Holds | `analyze()`: `store.begin()` (:520) precedes all `record_event` calls; checkpoint advance and `store.set_meta("last_ingest", ...)` happen before `store.commit()` (:571-580); the `ingest` error path calls `store.rollback()` before returning (:561-564), so no partial state can commit. |
| C3 | firewall_rules.rs:41-42 | "One PowerShell round-trip... avoid[s] a per-rule association lookup, which is unusably slow across ~500 rules." | Plausible, not independently benchmarked | The script batches `Get-NetFirewall*Filter -All` into hashtables keyed by `InstanceID` before a single `Get-NetFirewallRule` pipeline — O(n) hashtable joins, not O(n²) per-rule lookups. No live Windows host to benchmark directly. |
| C4 | store.rs:139-141 | "~10^4x fewer WAL commits than per-event autocommit." | Unverifiable (order-of-magnitude, not measured) | Directionally correct (one commit per ingest run vs. one per event); exact multiplier not measured in this review. |
| C5 | pipeline.rs:507-514 | "FilterOrigin is used only to label events that match no rule scope... in the Unattributed panel." | Holds | Confirmed: `ev.filter_origin` is only read inside the `matched.is_empty()` branches (pipeline.rs:544-551 and :254-257); never used for attribution when a scope match exists. |

## 5. Ground Truth appendix

No database schema beyond Firebreak's own local SQLite store exists in this repo's scope (no external DB to check against a live catalog). Physical/runtime facts used to judge findings:

- **Runtime:** Rust 2021 edition, `eframe`/`egui` 0.29 GUI, `rusqlite` 0.32 (bundled SQLite), single local SQLite file at `%ProgramData%\firebreak\firebreak.db`, WAL journal mode.
- **Deployment model:** on-demand GUI executable (no service/driver), always requires interactive Administrator elevation; also has `--no-ui`/`--enable-only`/`--collect`/`--reset`/`--restore-audit` headless CLI modes.
- **Cadence:** ingestion (`analyze()`) runs once per app launch/"Refresh now" click, not on a timer/schedule — so none of the performance findings from the skill's "cadence multiplies cost" principle apply at the severity they would for a hot-path/scheduled service; this materially changed the Pass 4 conclusions (no Medium+ performance findings were raised, since even an O(rules × listeners) or O(events × matched rules × 4 SQL writes) cost only pays once per manual run, not every 30 seconds).
- **Concurrency model:** single SQLite connection per `Store::open` call; ingestion, Apply, and update-check each spawn a dedicated `std::thread` communicating back to the egui thread via `mpsc` channels — no shared mutable state across threads beyond the `Arc<Mutex<UpdateState>>` for the update flow, which is used correctly (lock scoped to a snapshot read/write, never held across a blocking call).
- **Dependency versions (Cargo.lock):** `windows` is duplicated at 0.52.0 (transitive, via `rfd`/`winresource`) and 0.58.0 (direct) — increases compile time/binary size slightly but is not a security or correctness issue. `cargo-audit` was not available in this sandbox; a dependency CVE sweep was not performed and is recorded as a coverage gap, not asserted as clean.

## 6. Coverage appendix

All 29 tracked, non-vendored files were fully read (Pass 1 Understanding) and carried through Passes 2-5 and Pass V; see `.deep-review/ledger.md` for the per-file breakdown. `src/scope.rs` was reclassified from P2 to P1 mid-review once it became clear it was the core matching-correctness surface the accuracy focus area asked about — noted here for honesty about the initial priority call.

**Not independently verified (explicitly flagged, not glossed over):**
- No live Windows host was available in this sandbox. `cargo test` ran natively on Linux (46/46 pass — the suite is written to be host-independent via `#[cfg(windows)]` gating of the real WinAPI calls); `cargo clippy`/`cargo build` were cross-compiled for `x86_64-pc-windows-gnu` and succeeded, but nothing was *run* on Windows. This means: F3 could not be empirically reproduced (marked Suspected); the WFP/EvtQuery/audit-policy/ACL Win32 API call sites (audit_control.rs, elevation.rs, winpriv.rs, secure_dir.rs, event_query.rs's `win` module, winhttp.rs) were reviewed by code inspection and cross-checked against documented Win32 API contracts, not exercised.
- `cargo-audit` was not installed; no dependency CVE database check was performed.
- Claims C3/C4 (performance magnitude claims) are plausible-by-construction but not benchmarked.

**Fully read and clean (no findings) after all passes:** `app_identity.rs`, `baseline_checks.rs`, `console.rs`, `listeners.rs`, `model.rs`, `secure_dir.rs`, `store.rs`, `support.rs`, `syspath.rs`, `theme.rs`, `time_util.rs`, `winhttp.rs`, `winpriv.rs`, `build.rs`, `assets/collect.ps1`.

**Convergence:** one full sweep was run over all P1 files plus every file that produced a finding (scope.rs, pipeline.rs, main.rs, event_query.rs, update.rs, ui/paint.rs), specifically hunting for siblings of F1 (other enabled-state-gating omissions) and F2 (other flag-parsing swallow patterns). Findings from the sweep: none new at Medium+ (confirmed `listeners_for_rule` and `baseline_checks::flags_for`'s name/port checks intentionally don't gate on `enabled` — both are informational/advisory displays independent of "did this rule decide real traffic," not the same class of bug as F1; confirmed `--db` shares F2's root cause and was folded into that finding rather than reported separately). Sweep yielded zero new Medium+ findings, so convergence was reached after 1 sweep (well under the 3-sweep cap).

## 7. Positive observations

- **No injection surface anywhere.** All SQL is parameterized (`rusqlite::params!`); all PowerShell invocations pass a base64 `-EncodedCommand` blob built from a fixed script template with only rule names/controlled tokens interpolated, and those interpolations correctly escape embedded single quotes for PowerShell's single-quoted-string grammar.
- **Elevated-process hygiene.** `syspath.rs` hardcodes absolute `%SystemRoot%\System32\...` paths for every subprocess spawn instead of relying on `Command::new("x.exe")`'s PATH search — closes a real elevated-process PATH-hijack class of bug that's easy to miss.
- **Data-directory hardening.** `secure_dir.rs` creates `%ProgramData%\firebreak` with an explicit SYSTEM+Administrators DACL and refuses to trust a pre-existing directory unless it's owned by one of those principals — correctly defeats a non-admin pre-creating the world-writable `%ProgramData%` subdirectory to tamper with the DB/backups an admin later relies on.
- **Ingestion transactionality** is genuinely sound: single transaction per run, checkpoint advanced only alongside the writes it depends on, verified rollback on error. This is the kind of "crash-safe, idempotent, exactly-once" design the skill's own motivating example (the partitioned-BRIN-scan bug) was about catching the *absence* of — here it's actually present and correct.
- **Test discipline.** 46 tests, several explicitly written as regressions for named past bugs (`unconstrained_rule_is_excluded` — "regression for the 30-identical-rows bug"; `short_rule_name_cannot_swallow_filters` — "regression for C-04") — a team that clearly writes tests when it finds real bugs, which is exactly the practice that would have caught F1 with one more test case.
- **Backup-before-mutate discipline** in the Apply flow: every firewall rule change is preceded by a full `netsh advfirewall export` policy backup, and the Apply pipeline refuses to proceed if that backup fails — a good safety property for a tool that mutates live firewall policy.
