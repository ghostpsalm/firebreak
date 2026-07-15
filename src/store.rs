use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

use crate::model::{EventRecord, RuleInfo, RuleUsage};

pub struct Store {
    conn: Connection,
}

/// Default DB location: %ProgramData%\firebreak\firebreak.db (survives per-user
/// profile churn; tool runs elevated anyway).
pub fn default_db_path() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    Path::new(&base).join("firebreak").join("firebreak.db")
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            crate::secure_dir::ensure_secured_dir(dir)
                .with_context(|| format!("securing {}", dir.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening db {}", path.display()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- rolled-up usage per rule; rule_id is the firewall rule Name
            -- (InstanceID), or 'unmatched:<boot_session>:<filter_id>' for
            -- events whose filter never resolved to a rule
            CREATE TABLE IF NOT EXISTS rule_usage (
                rule_id     TEXT PRIMARY KEY,
                allow_count INTEGER NOT NULL DEFAULT 0,
                block_count INTEGER NOT NULL DEFAULT 0,
                first_seen  TEXT,
                last_seen   TEXT
            );

            CREATE TABLE IF NOT EXISTS rule_apps (
                rule_id   TEXT NOT NULL,
                app_path  TEXT NOT NULL,
                hits      INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT,
                PRIMARY KEY (rule_id, app_path)
            );

            -- WFP filter-id -> rule mapping, persisted per run and keyed by
            -- boot session (boot start time, ISO). Filter run-time IDs are
            -- only meaningful within one boot: the same numeric ID can name
            -- a different filter after a reboot, so a mapping must never be
            -- applied to events from another session.
            CREATE TABLE IF NOT EXISTS filter_map (
                filter_id    INTEGER NOT NULL,
                boot_session TEXT NOT NULL,
                rule_id      TEXT,
                filter_name  TEXT,
                mapped_via   TEXT,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY (filter_id, boot_session)
            );

            -- snapshot of the enabled rule set at audit-enable time and on
            -- each run, so "rule existed but never appeared" is answerable
            CREATE TABLE IF NOT EXISTS rule_snapshot (
                snapshot_at  TEXT NOT NULL,
                rule_json    TEXT NOT NULL
            );
            "#,
        )?;
        Ok(Store { conn })
    }

    // ---- transactions ----
    // Ingestion runs as one transaction: aggregation and the checkpoint
    // advance commit together, so a crash mid-ingest rolls back cleanly and
    // a rerun cannot double-count. Also ~10^4x fewer WAL commits than
    // per-event autocommit.

    pub fn begin(&self) -> Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        Ok(())
    }

    pub fn commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }

    pub fn rollback(&self) -> Result<()> {
        self.conn.execute_batch("ROLLBACK")?;
        Ok(())
    }

    // ---- meta / checkpoint ----

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare_cached("SELECT value FROM meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )?;
        stmt.execute(params![key, value])?;
        Ok(())
    }

    pub fn delete_meta(&self, key: &str) -> Result<()> {
        let mut stmt = self.conn.prepare_cached("DELETE FROM meta WHERE key = ?1")?;
        stmt.execute(params![key])?;
        Ok(())
    }

    /// Last-processed EventRecordID (Security channel). The next ingest
    /// resumes strictly after this record.
    pub fn checkpoint_record_id(&self) -> Result<Option<u64>> {
        Ok(self
            .get_meta("checkpoint_record_id")?
            .and_then(|v| v.parse().ok()))
    }

    pub fn set_checkpoint_record_id(&self, id: u64) -> Result<()> {
        self.set_meta("checkpoint_record_id", &id.to_string())
    }

    // ---- ingestion ----

    /// Record one event against a resolved rule id (or unmatched pseudo-id).
    /// Hot path — statements are cached, and the caller wraps the whole
    /// ingestion in one transaction via begin()/commit().
    pub fn record_event(&self, rule_id: &str, ev: &EventRecord, app_normalized: &str) -> Result<()> {
        let (allow, block) = if ev.is_allow() { (1, 0) } else { (0, 1) };
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO rule_usage (rule_id, allow_count, block_count, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(rule_id) DO UPDATE SET
                allow_count = allow_count + ?2,
                block_count = block_count + ?3,
                first_seen  = MIN(first_seen, ?4),
                last_seen   = MAX(last_seen, ?4)",
        )?;
        stmt.execute(params![rule_id, allow, block, ev.time_created])?;
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO rule_apps (rule_id, app_path, hits, last_seen)
             VALUES (?1, ?2, 1, ?3)
             ON CONFLICT(rule_id, app_path) DO UPDATE SET
                hits = hits + 1,
                last_seen = MAX(last_seen, ?3)",
        )?;
        stmt.execute(params![rule_id, app_normalized, ev.time_created])?;
        Ok(())
    }

    /// COALESCE keeps an earlier same-session mapping alive if the filter
    /// has since been deleted (rule removed mid-boot): a currently-unmatched
    /// re-sighting must not NULL out the mapping older events still need.
    pub fn upsert_filter_mapping(
        &self,
        filter_id: u64,
        boot_session: &str,
        rule_id: Option<&str>,
        filter_name: &str,
        mapped_via: &str,
        now_iso: &str,
    ) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO filter_map (filter_id, boot_session, rule_id, filter_name, mapped_via, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(filter_id, boot_session) DO UPDATE SET
                rule_id = COALESCE(excluded.rule_id, rule_id),
                filter_name = excluded.filter_name,
                mapped_via = CASE WHEN excluded.rule_id IS NULL AND rule_id IS NOT NULL
                                  THEN mapped_via ELSE excluded.mapped_via END,
                last_seen_at = excluded.last_seen_at",
        )?;
        stmt.execute(params![
            filter_id as i64,
            boot_session,
            rule_id,
            filter_name,
            mapped_via,
            now_iso
        ])?;
        Ok(())
    }

    /// Look up a recorded mapping for a filter id within a specific boot
    /// session — used for events from sessions other than the current one,
    /// and for current-session filters that no longer exist.
    pub fn historical_filter_rule(&self, filter_id: u64, boot_session: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT rule_id FROM filter_map
             WHERE filter_id = ?1 AND boot_session = ?2 AND rule_id IS NOT NULL",
        )?;
        let mut rows = stmt.query(params![filter_id as i64, boot_session])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    /// Keeps only the first snapshot (the rule set as it stood when
    /// collection started) and the latest — enough to answer "what changed
    /// since the audit began" without growing the DB on every run.
    pub fn snapshot_rules(&self, rules: &[RuleInfo], now_iso: &str) -> Result<()> {
        let json = serde_json::to_string(rules)?;
        self.conn.execute(
            "INSERT INTO rule_snapshot (snapshot_at, rule_json) VALUES (?1, ?2)",
            params![now_iso, json],
        )?;
        self.conn.execute(
            "DELETE FROM rule_snapshot WHERE snapshot_at NOT IN (
                (SELECT MIN(snapshot_at) FROM rule_snapshot),
                (SELECT MAX(snapshot_at) FROM rule_snapshot)
            )",
            [],
        )?;
        Ok(())
    }

    // ---- reporting ----

    /// All usage in two whole-table queries (instead of two per rule).
    /// Apps are ordered by hits within each rule.
    pub fn all_usage(&self) -> Result<std::collections::HashMap<String, RuleUsage>> {
        let mut map: std::collections::HashMap<String, RuleUsage> =
            std::collections::HashMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, allow_count, block_count, first_seen, last_seen FROM rule_usage",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RuleUsage {
                rule_id: row.get(0)?,
                allow_count: row.get(1)?,
                block_count: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
                apps: Vec::new(),
            })
        })?;
        for u in rows {
            let u = u?;
            map.insert(u.rule_id.clone(), u);
        }
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, app_path, hits FROM rule_apps ORDER BY rule_id, hits DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for r in rows {
            let (rule_id, app, hits) = r?;
            if let Some(u) = map.get_mut(&rule_id) {
                u.apps.push((app, hits));
            }
        }
        Ok(map)
    }

    #[allow(dead_code)]
    pub fn usage_for(&self, rule_id: &str) -> Result<Option<RuleUsage>> {
        let mut stmt = self.conn.prepare(
            "SELECT allow_count, block_count, first_seen, last_seen
             FROM rule_usage WHERE rule_id = ?1",
        )?;
        let mut rows = stmt.query(params![rule_id])?;
        let mut usage = match rows.next()? {
            Some(row) => RuleUsage {
                rule_id: rule_id.to_string(),
                allow_count: row.get(0)?,
                block_count: row.get(1)?,
                first_seen: row.get(2)?,
                last_seen: row.get(3)?,
                apps: Vec::new(),
            },
            None => return Ok(None),
        };
        let mut stmt = self.conn.prepare(
            "SELECT app_path, hits FROM rule_apps WHERE rule_id = ?1 ORDER BY hits DESC",
        )?;
        let rows = stmt.query_map(params![rule_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for r in rows {
            usage.apps.push(r?);
        }
        Ok(Some(usage))
    }

    /// All usage rows whose rule_id starts with 'unmatched:' — events we
    /// could not attribute to any firewall rule — most hits first.
    pub fn unmatched_usage(&self) -> Result<Vec<RuleUsage>> {
        let mut out: Vec<RuleUsage> = self
            .all_usage()?
            .into_values()
            .filter(|u| u.rule_id.starts_with("unmatched:"))
            .collect();
        out.sort_by_key(|u| -(u.allow_count + u.block_count));
        Ok(out)
    }
}
