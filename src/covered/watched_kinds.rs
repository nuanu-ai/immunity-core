//! How each kind of watched place was read, as the status tells it (`watched.kinds`), and which
//! kinds a reading speaks for, so that a cause of what is not covered names the rows it stands
//! beside (`Uncovered.watched_kinds`). Apart from `covered` only for its length.

use super::*;

/// How the latest readings of one kind of watched files on this Mac went together, as
/// `watched.kinds` tells it.
pub struct WatchedReadings {
    pub watched_as: &'static str,
    /// Its readings by completeness. A kind of its list with no reading here was not read, and
    /// counts as a reading of nothing.
    pub full: usize,
    pub partial: usize,
    pub none: usize,
    /// `None` when it has no reading here at all.
    pub coverage: Option<&'static str>,
    /// Why they were not full, each reason once; on one full reading that is all, its note.
    pub reason: Option<String>,
    /// When its latest reading here was taken; `None` with no reading.
    pub read_at: Option<i64>,
    /// Every reading of it here was taken by the latest full check and not dated ahead
    /// (`look::fresh`), and it has one.
    pub fresh: bool,
}

/// The kinds of watched files with their latest readings on this Mac (`this`), its checkouts'
/// among them. No false calm: a kind is `full` only when every coverage kind of its list has a
/// reading here and each is full, and a reading of another machine stands for none of them; and
/// `fresh` only when it has a reading and each was taken by the latest full check, which began at
/// `latest_run`, and is not dated ahead of `now`.
pub fn watched_readings(
    latest: &[Latest],
    this: Option<&str>,
    latest_run: Option<i64>,
    now: i64,
) -> Vec<WatchedReadings> {
    let here = |scope: &str| {
        this.is_some_and(|t| {
            let checkout = scope
                .strip_prefix("checkout:")
                .and_then(|s| s.strip_prefix(t));
            on_this_mac(scope, t) || checkout.is_some_and(|rest| rest.starts_with('/'))
        })
    };
    let mine: Vec<&Latest> = (latest.iter())
        .filter(|r| r.reader == watched::READER && here(&r.scope))
        .collect();
    let group = |(watched_as, kinds): (&'static str, Vec<String>)| {
        let rows: Vec<&Latest> = mine
            .iter()
            .copied()
            .filter(|r| kinds.contains(&r.kind))
            .collect();
        let count = |c: &str| rows.iter().filter(|r| r.completeness == c).count();
        let unread = (kinds.iter())
            .filter(|k| !rows.iter().any(|r| &r.kind == *k))
            .count();
        let unread = if rows.is_empty() { 0 } else { unread };
        let (full, partial, none) = (count("full"), count("partial"), count("none") + unread);
        let coverage = match (full, partial, none) {
            (0, 0, 0) => None,
            (_, 0, 0) => Some("full"),
            (0, 0, _) => Some("none"),
            _ => Some("partial"),
        };
        let mut reasons: Vec<&str> = Vec::new();
        for r in rows.iter().filter(|r| r.completeness != "full") {
            if let Some(reason) = r.reason.as_deref().filter(|x| !reasons.contains(x)) {
                reasons.push(reason);
            }
        }
        let reason = match (reasons.is_empty(), rows.as_slice()) {
            (false, _) => Some(reasons.join("; ")),
            (true, [only]) if unread == 0 => only.reason.clone(),
            _ => None,
        };
        WatchedReadings {
            watched_as,
            full,
            partial,
            none,
            coverage,
            reason,
            read_at: rows.iter().map(|r| r.at).max(),
            fresh: !rows.is_empty()
                && unread == 0
                && (rows.iter()).all(|r| crate::look::fresh(r.at, latest_run, now)),
        }
    };
    watched_files().into_iter().map(group).collect()
}

/// The watched places as the status gives them: each kind of watched files with how its latest
/// readings here went, when it was last read and whether that is fresh (`watched_readings`).
pub fn watched_message(
    st: &status::State,
    s: &status::Summary,
    w: &status::Watched,
    now: i64,
) -> v1::WatchedPlaces {
    use crate::contract::value_of;
    use crate::known::whole;
    use crate::status::{CHANGES_SHOWN, n};
    let mine: Vec<&Latest> = st
        .coverage
        .iter()
        .filter(|r| r.reader == watched::READER)
        .collect();
    let this = st.this_mac.machine.as_deref();
    let kinds = watched_readings(&st.coverage, this, Some(s.run.started_at), now)
        .into_iter()
        .map(|k| {
            let watched_as = k.watched_as;
            let presence = st
                .presence_only
                .get(watched_as)
                .copied()
                .unwrap_or_default();
            v1::WatchedKind {
                kind: watched_as.to_string(),
                files: n(st.files.get(watched_as).copied().unwrap_or_default()),
                presence_only: n(presence),
                presence_only_note: (presence > 0).then(|| watched::PRESENCE_ONLY.to_string()),
                coverage: k.coverage.map(value_of::<v1::Completeness>),
                readings: Some(v1::CompletenessCounts {
                    full: n(k.full),
                    partial: n(k.partial),
                    none: n(k.none),
                }),
                // The readers' reasons, prose from their sources: cut, as every such text.
                reason_text: k.reason.as_deref().map(crate::secrets::said),
                read_at: k.read_at,
                fresh: k.fresh,
            }
        })
        .collect();
    v1::WatchedPlaces {
        files: n(w.files),
        first_reading: w.first,
        since_last_reading: (!w.first).then(|| v1::PlaceCounts {
            new: n(w.new),
            changed: n(w.changed),
            gone: n(w.gone),
        }),
        kinds,
        content_not_read: n(mine
            .iter()
            .filter(|r| r.kind == watched::CONTENT && r.completeness != "full")
            .count()),
        changes: s
            .changes
            .iter()
            .rev()
            .take(CHANGES_SHOWN)
            .map(|c| v1::PlaceChange {
                at: c.at,
                run_id: c.run_id.clone(),
                change: crate::finding_answer::change_of(c.change),
                kind: c.kind.clone(),
                path_text: whole(&c.path),
            })
            .collect(),
        changes_total: n(s.changes.len()),
    }
}

/// The kinds of watched place some readings, each a reader, a kind and a scope, speak for, each
/// once. The reading of a watched file's content speaks for the kind the file is watched as.
pub fn kinds_read_by<'a>(
    conn: &Connection,
    readings: impl Iterator<Item = (&'a str, &'a str, &'a str)>,
) -> rusqlite::Result<Vec<&'static str>> {
    let mut out: Vec<&'static str> = Vec::new();
    let mut watched_as = conn.prepare(
        "SELECT object FROM assertion WHERE subject = ?1 AND predicate = 'watched_as'
         ORDER BY layer = 'live' DESC, id DESC LIMIT 1",
    )?;
    for (reader, kind, scope) in readings {
        let kinds = match reader == watched::READER && kind == watched::CONTENT {
            true => {
                let of: Option<String> = watched_as.query_row([scope], |r| r.get(0)).optional()?;
                (watched_files().into_iter().map(|(as_, _)| as_))
                    .filter(|as_| of.as_deref() == Some(*as_))
                    .collect()
            }
            false => kinds_of_reading(reader, kind),
        };
        for kind in kinds {
            if !out.contains(&kind) {
                out.push(kind);
            }
        }
    }
    Ok(out)
}

/// The kinds of watched place a reading speaks for, in the words of `WatchedKind.kind` and
/// `IntegrityReading.kind`, or `DEPENDENCIES`: the kind of watched files whose list holds its
/// kind, its kind of installed software, the packages for a reading of lockfiles, and for a
/// reading that finds projects every kind kept in projects and the packages.
fn kinds_of_reading(reader: &str, kind: &str) -> Vec<&'static str> {
    let rows = watched().into_iter().map(|(count, ..)| count);
    if reader == watched::READER {
        let files = watched_files().into_iter();
        return (files.filter(|(_, k)| k.iter().any(|k| k == kind)))
            .map(|(as_, _)| as_)
            .collect();
    }
    if reader == crate::lockfiles::READER {
        return vec![DEPENDENCIES];
    }
    if (crate::project::FOUND_BY.iter()).any(|(by, of)| reader == *by && kind == *of) {
        return (rows.filter(|c| in_projects(*c)))
            .filter_map(|c| match c {
                Count::Files(as_) => Some(as_),
                _ => None,
            })
            .chain([DEPENDENCIES])
            .collect();
    }
    (rows.filter(|_| reader == integrity::READER))
        .filter_map(|c| match c {
            Count::Installed(of) if of == kind => Some(of),
            _ => None,
        })
        .collect()
}
