//! The latest reading of each reader, scope and kind, which the status, `covered`, `known` and
//! `vulnerabilities` count coverage from.

use rusqlite::Connection;

/// The latest coverage record of one reader, scope and kind.
#[derive(Clone, Default)]
pub struct Latest {
    /// Its row of `coverage`.
    pub id: i64,
    pub reader: String,
    pub scope: String,
    pub kind: String,
    pub completeness: String,
    pub reason: Option<String>,
    /// Why it is incomplete, as `coverage.cause` holds it; `None` on a full reading and on
    /// a reading written before causes were kept.
    pub cause: Option<String>,
    pub at: i64,
    pub last_full: Option<i64>,
    /// What it did not read (`store::unread_of`); none on a full reading.
    pub unread: Vec<crate::store::Unread>,
}

/// The latest record for each reader, scope and kind, and its latest full one, with what each
/// did not read.
/// Readings that are not full come first. Readings inside a container or checkout that
/// is gone no longer count and are left out. `immunity status` counts coverage from this too.
pub fn latest_coverage(conn: &Connection) -> rusqlite::Result<Vec<Latest>> {
    let mut latest: Vec<Latest> = conn
        .prepare(&format!(
            "{latest}
         SELECT c.reader, c.scope, c.kind, c.completeness, c.reason, c.observed_at,
                (SELECT MAX(f.observed_at) FROM coverage f
                 WHERE f.reader = c.reader AND f.scope = c.scope AND f.kind = c.kind
                   AND f.completeness = 'full'),
                c.cause, c.id
         FROM latest c
         WHERE NOT {gone}
         ORDER BY c.completeness = 'full', c.completeness, c.reader, c.scope, c.kind",
            latest = crate::store::LATEST,
            gone = crate::store::gone_entity("c.scope")
        ))?
        .query_map([], |r| {
            Ok(Latest {
                reader: r.get(0)?,
                scope: r.get(1)?,
                kind: r.get(2)?,
                completeness: r.get(3)?,
                reason: r.get(4)?,
                at: r.get(5)?,
                last_full: r.get(6)?,
                cause: r.get(7)?,
                id: r.get(8)?,
                unread: Vec::new(),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut not_full: Vec<&mut Latest> = (latest.iter_mut())
        .filter(|r| r.completeness != "full")
        .collect();
    let ids: Vec<i64> = not_full.iter().map(|r| r.id).collect();
    for (r, rows) in not_full
        .iter_mut()
        .zip(crate::store::unread_of(conn, &ids)?)
    {
        r.unread = rows;
    }
    Ok(latest)
}
