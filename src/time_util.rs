//! Small time helpers for the header and table: relative "4 min ago"
//! strings and evidence-age in hours. Parses the ISO8601 UTC timestamps the
//! store keeps.

use chrono::{DateTime, Utc};

fn parse(iso: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(iso)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

pub fn hours_since(iso: &str) -> Option<f64> {
    let then = parse(iso)?;
    Some((Utc::now() - then).num_seconds() as f64 / 3600.0)
}

/// "4 min ago", "2 h ago", "6 d ago", "just now". "never" passthrough is
/// handled by the caller (None usage).
pub fn relative(iso: &str) -> String {
    let Some(then) = parse(iso) else {
        return iso.to_string();
    };
    let secs = (Utc::now() - then).num_seconds().max(0);
    if secs < 45 {
        "just now".into()
    } else if secs < 90 {
        "1 min ago".into()
    } else if secs < 3600 {
        format!("{} min ago", secs / 60)
    } else if secs < 7200 {
        "1 h ago".into()
    } else if secs < 86_400 {
        format!("{} h ago", secs / 3600)
    } else if secs < 172_800 {
        "1 d ago".into()
    } else {
        format!("{} d ago", secs / 86_400)
    }
}

/// "Tue Jun 30, 07:12 (15 days)" style, for the auditing-since header stat.
pub fn since_with_age(iso: &str) -> String {
    let Some(then) = parse(iso) else {
        return iso.to_string();
    };
    let days = (Utc::now() - then).num_days().max(0);
    let stamp = then.format("%a %b %-d, %H:%M");
    let age = if days == 0 {
        let hours = (Utc::now() - then).num_hours().max(0);
        format!("{hours} h")
    } else if days == 1 {
        "1 day".into()
    } else {
        format!("{days} days")
    };
    format!("{stamp} ({age})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_buckets() {
        assert_eq!(relative("not-a-date"), "not-a-date");
        // a clearly-old timestamp reads in days
        assert!(relative("2000-01-01T00:00:00Z").ends_with("d ago"));
    }

    #[test]
    fn hours_since_positive_for_past() {
        assert!(hours_since("2000-01-01T00:00:00Z").unwrap() > 0.0);
        assert!(hours_since("bad").is_none());
    }
}
