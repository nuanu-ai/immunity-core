//! The view: a small summary page that answers what the app answers, and pages of details
//! next to it with the big tables. It only reads. Nothing from the network: plain HTML,
//! `<details>` and inline CSS. One script, fixed in the program and named by one fixed tag,
//! keeps the numbers of "As it happens" fresh while the summary is open (`happens.rs`) and
//! copies a finding's command for an agent; no other page has one, and nothing from the store
//! ever becomes script.
//!
//! Invariant: every piece of text that comes from the store goes through `esc`
//! before it enters the page. Names, versions, reasons and source references are
//! partly written by an attacker and must never become markup.

use rusqlite::{Connection, OptionalExtension, params};
use std::error::Error;
use std::fmt::Write;

/// The runs the changes page lists (`store::listed_runs`).
const RUNS_SHOWN: i64 = crate::store::RUNS_KEPT;
/// The most kinds of watched places a watcher's reading is named by on the changes page.
const KINDS_NAMED: usize = 3;
/// The latest run is shown open only when its changes fit on a screen or a few.
const EVENTS_SHOWN_OPEN: usize = 500;

pub type Out = Result<(), Box<dyn Error>>;

/// The summary page, in the store's folder.
pub const SUMMARY: &str = "view.html";

/// The folder next to the summary page that holds the pages of details.
pub const DETAILS: &str = "view";

/// What the pages were made from and when, written after them, relative to the store's folder.
pub const MADE: &str = "view/made.json";

/// How long pages stand as current while nothing in their basis moved, in seconds. What
/// changes with time alone, such as an answer that expires or how old the last check is, is
/// shown at most this late; every page says when it was made.
pub const CURRENT_FOR: i64 = 3600;

/// What the pages rest on that changes without the clock: the journal's latest entry (every
/// change, finding raised or answered, owner's word, run and reading of threat data), what
/// each latest reading covered, the watcher that holds the store and what failed in it, and
/// the program that writes the pages. Equal bases make the same pages, but for the time
/// they were made, the latest sample's counts, and what the event level records, which pages
/// show with their time. What the event level records has a basis of its own,
/// `events::basis`, kept beside this one in `MADE`: when only it moved, the pages that show it
/// are written again (`event_pages`). Cheap: a lookup by key, the latest readings and a lock.
pub fn basis(conn: &Connection, folder: &std::path::Path) -> Result<String, Box<dyn Error>> {
    use std::hash::{Hash, Hasher};
    // The latest journal entry but a `matched` one, which says a published rule matched in a
    // reading: what it counts is the event level's and moves `events::basis`, and no page shows
    // the entry itself. A match that raises or reopens a finding writes the finding's own entry
    // in the same transaction, which moves this. Walked from the newest, so a run of `matched`
    // entries is skipped, not the journal scanned.
    let journal: i64 = conn
        .query_row(
            "SELECT seq FROM journal WHERE entry != 'matched' ORDER BY seq DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    // A reading's time and id are new at every reading; what it covered is not.
    let mut covered = std::collections::hash_map::DefaultHasher::new();
    for l in latest_coverage(conn)? {
        (l.reader, l.scope, l.kind, l.completeness, l.reason, l.cause).hash(&mut covered);
    }
    let watcher = crate::watch::basis(conn, folder)?;
    let program = std::env::current_exe()?;
    let meta = std::fs::metadata(&program)?;
    Ok(format!(
        "journal {journal}; covered {:016x}; watcher {watcher}; program {} {} {:?}",
        covered.finish(),
        program.display(),
        meta.len(),
        meta.modified()?
    ))
}

/// What the commands answer, built in process from the read the pages are made in, which the
/// pages are drawn from: so a page shows what the command shows and decides nothing again.
pub struct Answers<'a> {
    /// `immunity findings`.
    pub findings: crate::contract::v1::Findings,
    /// `immunity finding <id>` for a finding a page opens; `None` for an id the store does not
    /// hold.
    pub finding: Box<FindingOf<'a>>,
    /// `immunity rules`, of the event level the status rests on.
    pub rules: crate::contract::v1::Rules,
    /// `immunity owner`: the statements that stand, and the machines beyond this Mac.
    pub statements: crate::contract::v1::Statements,
    /// `immunity machine <id>` for a machine a page opens, with `--files-anywhere` when asked;
    /// `None` when it names no one machine.
    pub machine: Box<MachineOf<'a>>,
    /// `immunity vulnerabilities`: `None` where only the pages that show the event level are
    /// written.
    pub vulnerabilities: Option<crate::contract::v1::Vulnerabilities>,
}

/// `immunity machine <id>` as the pages ask it, by an id as the contract gives it, and with
/// `--files-anywhere` when the second is true.
pub type MachineOf<'a> =
    dyn Fn(&str, bool) -> rusqlite::Result<Option<crate::contract::v1::Known>> + 'a;

/// `immunity finding <id>` as the pages ask it.
pub type FindingOf<'a> =
    dyn Fn(&str) -> rusqlite::Result<Option<crate::contract::v1::Finding>> + 'a;

#[cfg(test)]
impl Answers<'_> {
    /// No finding, and the rules with no reading of the event level.
    pub fn none() -> Answers<'static> {
        Answers {
            findings: Default::default(),
            finding: Box::new(|_| Ok(None)),
            rules: Default::default(),
            statements: Default::default(),
            machine: Box::new(|_, _| Ok(None)),
            vulnerabilities: None,
        }
    }
}

/// Every page the view writes, as its path relative to the store's folder and its HTML: the
/// summary first, then the pages its links lead a person to (`pages.rs`), then one technical
/// page for each of the big tables. The summary and the pages of this Mac, of vulnerabilities and
/// of threat data are drawn from what the commands answer (`Answers`, and the result `immunity
/// status --json` gives), so the two say the same; the technical pages are what the store holds,
/// reached from one line at the bottom of the summary.
pub fn pages(
    conn: &Connection,
    result: &crate::contract::v1::Status,
    answers: &Answers,
    store: &str,
    now: i64,
) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let latest = latest_coverage(conn)?;
    // This Mac's page lists every watched file on it, so it asks as `immunity machine <this Mac>
    // --files-anywhere` does.
    let this = (result.this_mac.as_ref()).and_then(|m| m.id_text.as_deref());
    let machine = match this {
        Some(id) => (answers.machine)(id, true)?,
        None => None,
    };
    let vulnerabilities = answers.vulnerabilities.clone().unwrap_or_default();
    let mut pages = vec![
        (
            SUMMARY.to_string(),
            crate::pages::summary(result, answers, now)?,
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::THIS_MAC),
            crate::pages::this_mac::page(result, machine.as_ref(), now),
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::BEYOND),
            crate::pages::beyond::page(result, &answers.statements, &answers.machine, now)?,
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::TECHNICAL),
            crate::pages::technical(),
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::VULNERABILITIES),
            crate::pages::vulnerabilities::page(&vulnerabilities, result, now),
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::THREAT_DATA),
            crate::pages::vulnerabilities::threat_data(result, now),
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::RULES),
            crate::pages::rules::page(&answers.rules, result, now),
        ),
    ];
    for (name, title) in DETAIL_PAGES {
        let mut body = String::new();
        match name {
            "coverage" => coverage(conn, &mut body, &latest, now)?,
            "changes" => changes(conn, &mut body)?,
            "gone" => retracted(conn, &mut body)?,
            _ => vocabulary(conn, &mut body)?,
        }
        let mut out = head(title);
        out.push_str(
            "<nav class=\"meta\"><a href=\"../view.html\">← What needs a look</a></nav>\n",
        );
        header(conn, &mut out, store, now)?;
        out.push_str(&body);
        out.push_str(FOOT);
        pages.push((format!("{DETAILS}/{name}.html"), out));
    }
    for (anchor, title) in SECTIONS {
        pages.push((section_file(anchor), section_page(anchor, title)));
    }
    Ok(pages)
}

/// The pages that show what the event level counts, as `pages` makes them: the summary and the
/// page of rules. When only `events::basis` moved since the pages were made, these alone are
/// written again.
pub fn event_pages(
    result: &crate::contract::v1::Status,
    answers: &Answers,
    now: i64,
) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    Ok(vec![
        (
            SUMMARY.to_string(),
            crate::pages::summary(result, answers, now)?,
        ),
        (
            format!("{DETAILS}/{}.html", crate::pages::RULES),
            crate::pages::rules::page(&answers.rules, result, now),
        ),
    ])
}

/// The sections of the summary something outside the page may ask for, by anchor and
/// title. Each has a page of its own that only sends the browser on to it, because macOS
/// can lose the `#section` of a file URL when it hands one to the browser.
pub const SECTIONS: [(&str, &str); 6] = [
    ("watched-here", "What is watched"),
    (
        "vulnerabilities",
        "Known vulnerabilities in packages your projects use",
    ),
    ("you-can-fix", "You can fix"),
    ("limits", "Could not be read on this Mac"),
    ("answered", "Answered"),
    ("as-it-happens", "As it happens"),
];

/// Where a section's own page is, relative to the store's folder.
pub fn section_file(anchor: &str) -> String {
    format!("{DETAILS}/section-{anchor}.html")
}

/// The files of the sections for a store, as anchor and absolute path: what
/// `immunity status --json` names so that nothing outside builds these paths.
pub fn section_files(store: &std::path::Path) -> Vec<(&'static str, std::path::PathBuf)> {
    let folder = store.parent().unwrap_or(std::path::Path::new("."));
    SECTIONS
        .iter()
        .map(|(anchor, _)| (*anchor, folder.join(section_file(anchor))))
        .collect()
}

/// A page that only sends the browser on to the summary at one section, with a plain link
/// for a browser that does not follow the refresh. No script.
fn section_page(anchor: &str, title: &str) -> String {
    let target = format!("../{SUMMARY}#{}", esc(anchor));
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta http-equiv=\"refresh\" content=\"0; url={target}\">\n<title>{title}</title>\n\
         </head>\n<body>\n<p><a href=\"{target}\">{title}</a></p>\n</body>\n</html>\n",
        title = esc(title)
    )
}

/// The pages of details, by file name and title.
pub const DETAIL_PAGES: [(&str, &str); 4] = [
    ("coverage", "What was read and how completely"),
    ("changes", "Changes"),
    ("gone", "No longer there"),
    ("vocabulary", "Vocabulary"),
];

pub const FOOT: &str = "</main>\n</body>\n</html>\n";

pub fn head(title: &str) -> String {
    HEAD.replace(
        "<title>What the store holds</title>",
        &format!("<title>{}</title>", esc(title)),
    )
}

/// `15,617 components`.
pub fn counted(n: i64, one: &str, many: &str) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    format!("{out} {}", if n == 1 { one } else { many })
}

/// Who gave an answer, as the owner reads it after the answer.
pub fn given_by(via: crate::findings::Via) -> &'static str {
    match via {
        crate::findings::Via::App => "in the app",
        crate::findings::Via::Agent => "through your agent",
        crate::findings::Via::Command => "from the command line",
        crate::findings::Via::Unknown => "how it came is not recorded",
    }
}

/// Makes text safe to put anywhere in the page, inside elements and inside quoted attributes.
/// Characters that could reorder or hide text are shown escaped, as `shown` shows them. This is
/// the one place a page writes a name, such as a path or a server's name, and any other text not
/// already in the form `secrets::said` gives: a backslash is written `\u{5c}`, as `Text::ours`
/// shows a name, so no name reads as a mark. One that already begins a `\u{…}`, as in a name the
/// contract gives, is kept, which can read as an escaped character and never as a mark. Text
/// that holds marks goes through `esc_said`.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.char_indices() {
        if c == '\\' && !escape_at(&s[i..]) {
            out.push_str("\\u{5c}");
        } else {
            esc_char(&mut out, c);
        }
    }
    out
}

/// `esc` for text already in the form `secrets::said` gives, or a contract's field that holds
/// marks: each bare backslash is the start of a mark the core made or of a `\u{…}`, kept.
pub fn esc_said(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        esc_char(&mut out, c);
    }
    out
}

/// Whether `s` begins with a character written `\u{…}`: one to six hex digits and a brace.
fn escape_at(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("\\u{") else {
        return false;
    };
    let hex = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
    (1..=6).contains(&hex) && rest.as_bytes().get(hex) == Some(&b'}')
}

/// One character as a page writes it.
fn esc_char(out: &mut String, c: char) {
    match c {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '"' => out.push_str("&quot;"),
        '\'' => out.push_str("&#39;"),
        c if crate::icu::hidden(c) => out.extend(c.escape_unicode()),
        _ => out.push(c),
    }
}

/// Text as the terminal may show it: every character that is hidden is written as
/// `\u{…}`. The store keeps the text as it was read; only what is shown is escaped.
pub fn shown(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if crate::icu::hidden(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// What a source said, such as why a reader could not read a place, as every output shows it
/// (`secrets::said`). A page escapes it with `esc`, as any other text.
pub use crate::secrets::said;

/// UTC seconds as `YYYY-MM-DD HH:MM UTC`.
pub fn utc(secs: i64) -> String {
    let (date, rest) = civil(secs);
    format!("{date} {:02}:{:02} UTC", rest / 3600, rest % 3600 / 60)
}

/// UTC seconds as ISO 8601 in UTC, `YYYY-MM-DDTHH:MM:SSZ`, for the machine-readable form.
pub fn iso(secs: i64) -> String {
    let (date, rest) = civil(secs);
    format!(
        "{date}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The date `YYYY-MM-DD` and the seconds into that day, from the civil-from-days algorithm.
fn civil(secs: i64) -> (String, i64) {
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (format!("{year:04}-{month:02}-{day:02}"), rest)
}

/// The date `YYYY-MM-DD` and the time `HH:MM` of UTC seconds in the Mac's own time zone, as
/// macOS converts them (`localtime_r`, which reads the zone the system or `TZ` names). Turning
/// a time into a zone's is someone else's logic, with its rules of summer time; it is not
/// written here. `None` when the system cannot convert it.
pub fn local(secs: i64) -> Option<(String, String)> {
    let t: libc::time_t = secs;
    // SAFETY: `localtime_r` writes only into `tm`, which lives through the call, and reads `t`.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return None;
    }
    Some((
        format!(
            "{:04}-{:02}-{:02}",
            i64::from(tm.tm_year) + 1900,
            tm.tm_mon + 1,
            tm.tm_mday
        ),
        format!("{:02}:{:02}", tm.tm_hour, tm.tm_min),
    ))
}

/// A time as the person's pages show it: in the Mac's time zone, the time alone on the day of
/// `now` and the date with it on any other, with the time in UTC as its tooltip and its machine
/// form in `datetime`. Only digits and fixed words: nothing from the Mac enters it.
pub fn when(secs: i64, now: i64) -> String {
    let shown = match (local(secs), local(now)) {
        (Some((day, time)), Some((today, _))) if day == today => time,
        (Some((day, time)), _) => format!("{day} {time}"),
        (None, _) => utc(secs),
    };
    format!(
        "<time datetime=\"{}\" title=\"{}\">{shown}</time>",
        iso(secs),
        utc(secs)
    )
}

pub fn utc_or(secs: Option<i64>, missing: &str) -> String {
    secs.map(utc).unwrap_or_else(|| missing.to_string())
}

/// Place, ecosystem and name from `component:<place>/<ecosystem>/<name>`. The place is
/// an entity id and may hold slashes; a scoped npm name (`@scope/name`) holds one too, and
/// a Homebrew name from a tap other than core, `<user>/<tap>/<name>`, holds two.
fn split_component(id: &str) -> Option<(&str, &str, &str)> {
    let rest = id.strip_prefix("component:")?;
    let (head, name) = rest.rsplit_once('/')?;
    let (place, ecosystem) = head.rsplit_once('/')?;
    let whole = |place: &'_ str, ecosystem: &'_ str| &rest[place.len() + ecosystem.len() + 2..];
    if ecosystem.starts_with('@') {
        let (place, ecosystem) = place.rsplit_once('/')?;
        return Some((place, ecosystem, whole(place, ecosystem)));
    }
    if let Some((tapped, _user)) = place.rsplit_once('/')
        && let Some((place, ecosystem)) = tapped.rsplit_once('/')
        && matches!(ecosystem, "brew" | "brew-cask")
    {
        return Some((place, ecosystem, whole(place, ecosystem)));
    }
    Some((place, ecosystem, name))
}

/// Ecosystem and name of a component, or no ecosystem and the whole id for anything else.
pub fn component_name(id: &str) -> (&str, &str) {
    split_component(id).map_or(("", id), |(_, ecosystem, name)| (ecosystem, name))
}

/// Where a component is, or nothing for anything else.
pub fn component_place(id: &str) -> &str {
    split_component(id).map_or("", |(place, _, _)| place)
}

/// The time and how many whole days ago it was, or that it is ahead of the clock
/// (`store::age`).
pub(crate) fn utc_age(secs: i64, now: i64) -> String {
    match crate::store::age(secs, now).map(|age| age / 86_400) {
        Some(1) => format!("{} · 1 day ago", utc(secs)),
        Some(days) => format!("{} · {days} days ago", utc(secs)),
        None => format!("{} · ahead of this Mac's clock", utc(secs)),
    }
}

/// The predicate in plain words where there is one.
fn what(predicate: &str) -> &str {
    match predicate {
        "part_of" => "present on",
        "has_version" => "version",
        "located_on" => "located on",
        "runs_os" => "operating system",
        "runs_platform" => "system, as the private network names it",
        "runs_kernel" => "kernel",
        "runs_image" => "image",
        "known_as" => "known as",
        "same_as" => "same machine as",
        other => other,
    }
}

/// A table cell with escaped text and an optional class.
pub fn td(out: &mut String, class: &str, text: &str) -> Out {
    cell(out, class, &esc(text))
}

/// `td` for text in the form `secrets::said` gives, which holds marks (`esc_said`).
pub fn td_said(out: &mut String, class: &str, text: &str) -> Out {
    cell(out, class, &esc_said(text))
}

pub(crate) fn cell(out: &mut String, class: &str, html: &str) -> Out {
    if class.is_empty() {
        write!(out, "<td>{html}</td>")?;
    } else {
        write!(out, "<td class=\"{class}\">{html}</td>")?;
    }
    Ok(())
}

/// A cell that shows a component's name and keeps its full id as a tooltip.
fn td_component(out: &mut String, id: &str) -> Out {
    write!(
        out,
        "<td title=\"{}\">{}</td>",
        esc(id),
        esc(component_name(id).1)
    )?;
    Ok(())
}

pub fn thead(out: &mut String, columns: &[&str]) {
    out.push_str("<thead><tr>");
    for c in columns {
        out.push_str("<th>");
        out.push_str(c);
        out.push_str("</th>");
    }
    out.push_str("</tr></thead>\n<tbody>\n");
}

fn header(conn: &Connection, out: &mut String, store: &str, now: i64) -> Out {
    let version: String = conn.query_row(
        "SELECT value FROM meta WHERE key = 'format_version'",
        [],
        |r| r.get(0),
    )?;
    let finished = crate::status::latest_finished(conn)?.and_then(|m| m.finished_at);
    write!(
        out,
        "<header>\n<h1>What the store holds</h1>\n<p class=\"meta\">Generated {} · store <span class=\"mono\">{}</span> · format version {} · last run finished {}</p>\n</header>\n",
        utc(now),
        esc(store),
        esc(&version),
        utc_or(finished, "never")
    )?;
    Ok(())
}

/// The latest run, by the order of the journal, if it never wrote `run_finished`.
fn unfinished_latest_run(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    let latest: Option<(i64, bool)> = conn
        .query_row(
            "SELECT at, EXISTS (SELECT 1 FROM journal f
                                WHERE f.run_id = j.run_id AND f.entry = 'run_finished')
             FROM journal j WHERE entry = 'run_started' ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })?;
    Ok(latest.and_then(|(at, finished)| (!finished).then_some(at)))
}

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

/// A completeness as the owner reads it: what is known and what is not. A full reading
/// with a note had nothing to read, which is not the same as having read something.
fn completeness_label<'a>(completeness: &'a str, note: Option<&str>) -> &'a str {
    match (completeness, note) {
        ("full", Some(_)) => "nothing to read",
        ("none", _) => "could not be read",
        ("partial", _) => "partial, removals unknown",
        (other, _) => other,
    }
}

pub(crate) fn badge(out: &mut String, completeness: &str, note: Option<&str>) -> Out {
    write!(
        out,
        "<span class=\"badge {}\">{}</span>",
        if completeness == "full" {
            "good"
        } else {
            "bad"
        },
        esc(completeness_label(completeness, note))
    )?;
    Ok(())
}

fn coverage(conn: &Connection, out: &mut String, rows: &[Latest], now: i64) -> Out {
    out.push_str("<section id=\"coverage\">\n<h2>What was read and how completely</h2>\n");
    out.push_str("<p class=\"muted\">Everything below is only as good as this.</p>\n");
    if let Some(at) = unfinished_latest_run(conn)? {
        writeln!(
            out,
            "<p class=\"alert\">The latest run started at {} and never finished. Nothing it read is in the store.</p>",
            utc(at)
        )?;
    }
    // The content of each watched file and the hooks of each checkout are readings of their
    // own; those read in full are shown under watched places, not here. A checkout in which the
    // reading of lockfiles found none is named under machines, as a checkout without a lockfile.
    let per_thing = [crate::watched::CONTENT, crate::watched::HOOK_KIND];
    let rows: Vec<&Latest> = rows
        .iter()
        .filter(|r| !per_thing.contains(&r.kind.as_str()) || r.completeness != "full")
        .filter(|r| r.reason.as_deref() != Some(crate::lockfiles::NONE_FOUND_NOTE))
        .collect();
    if rows.is_empty() {
        out.push_str("<p class=\"alert\">Nothing has been read yet.</p>\n</section>\n");
        return Ok(());
    }
    let not_full = rows.iter().filter(|r| r.completeness != "full").count();
    let partial = rows.iter().filter(|r| r.completeness == "partial").count();
    if not_full == 0 {
        out.push_str("<p class=\"ok\">Every reading was full at its latest run.</p>\n");
    } else {
        writeln!(
            out,
            "<p class=\"alert\">{not_full} of {} readings were not full at their latest run. \
             What they cover below may be out of date or missing.</p>",
            rows.len()
        )?;
    }
    if partial > 0 {
        writeln!(
            out,
            "<p class=\"alert\">{partial} of them were partial: what they saw was added, \
             but what disappeared there cannot be seen. Removals there are unknown.</p>"
        )?;
    }

    out.push_str("<div class=\"scroll\"><table>\n");
    thead(
        out,
        &[
            "Reader",
            "Where",
            "What",
            "Completeness",
            "Why, or what was there",
            "Last read",
            "Last full read",
        ],
    );
    for r in rows {
        let full = r.completeness == "full";
        out.push_str(if full { "<tr>" } else { "<tr class=\"bad\">" });
        td(out, "", &r.reader)?;
        td(out, "mono", &r.scope)?;
        td(out, "", &r.kind)?;
        out.push_str("<td>");
        badge(out, &r.completeness, r.reason.as_deref())?;
        out.push_str("</td>");
        td_said(
            out,
            "",
            &r.reason.as_deref().map_or_else(
                || (if full { "" } else { "no reason given" }).to_string(),
                said,
            ),
        )?;
        td(out, "nowrap", &utc_age(r.at, now))?;
        let last = if full {
            "this one".to_string()
        } else {
            utc_or(r.last_full, "never")
        };
        td(out, "nowrap", &last)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n</section>\n");
    Ok(())
}

pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn changes(conn: &Connection, out: &mut String) -> Out {
    write!(
        out,
        "<section id=\"changes\">\n<h2>Changes</h2>\n<p class=\"muted\">The last {RUNS_SHOWN} runs, newest first.</p>\n"
    )?;
    // The runs whose every reading the store keeps (`store::listed_runs`), so that what the page
    // says of each does not change when older readings are folded.
    let runs = crate::store::listed_runs(conn)?;
    if runs.is_empty() {
        out.push_str("<p>No runs yet.</p>\n");
    }

    // Whether a partial reading ever made an assertion: one that never did has nothing
    // that could be removed, so removals there are not unknown.
    let mut not_full_stmt = conn.prepare(
        "SELECT scope, kind, completeness, reason,
                EXISTS (SELECT 1 FROM assertion a WHERE a.layer IN ('live', 'retracted')
                          AND a.reader = c.reader AND a.scope = c.scope AND a.kind = c.kind)
         FROM coverage c
         WHERE run_id = ?1 AND completeness != 'full'
         ORDER BY completeness, scope, kind",
    )?;
    // Scopes read before this run and not read by it: nothing is known about them.
    let mut not_repeated_stmt = conn.prepare(&format!(
        "{}
         SELECT COUNT(*) FROM reading r
         WHERE (SELECT c.id FROM coverage c
                WHERE c.reader = r.reader AND c.scope = r.scope AND c.kind = r.kind
                ORDER BY c.id LIMIT 1) < (SELECT MIN(id) FROM coverage WHERE run_id = ?1)
           AND r.scope NOT IN (SELECT scope FROM coverage WHERE run_id = ?1)
           AND NOT {}",
        crate::store::LATEST,
        crate::store::gone_entity("r.scope")
    ))?;
    // What a watcher's reading read: the kinds its readings are of, a file's content aside.
    let mut kinds_stmt = conn.prepare(
        "SELECT DISTINCT kind FROM coverage WHERE run_id = ?1 AND kind != ?2 ORDER BY kind",
    )?;
    for (i, run) in runs.iter().enumerate() {
        let (run_id, at, finished, report) = (&run.run_id, &run.at, &run.finished, &run.report);
        // Counted as the report and `immunity status` count them: what was read for the first
        // time is the baseline, shown as such and never as added.
        let (since, first, events) = crate::status::run_changes(conn, run_id)?;
        let not_full: Vec<(String, String, String, Option<String>, bool)> = not_full_stmt
            .query_map([run_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        // A watcher's reading, `immunity watch`, reads only the watched places and never finishes
        // a run: it is shown as a watcher's reading, not as a run that did not finish.
        let sampled = run_id.starts_with(crate::processes::RUN_PREFIX);
        let watcher = run_id.starts_with(crate::watch::RUN_PREFIX) || sampled;
        let not_repeated: i64 = if watcher {
            0
        } else {
            not_repeated_stmt.query_row([run_id], |r| r.get(0))?
        };
        let partial = not_full.iter().any(|r| r.2 == "partial" && r.4);
        // The event level keeps no facts: a reading of it that read nothing hides no change.
        let nothing = not_repeated > 0
            || not_full.iter().any(|r| {
                r.2 == "none" && r.1 != crate::events::KIND && r.1 != crate::events::KIND_FILES
            });

        // No events is "no changes" only when the run finished, read everything in full
        // and read again every scope read before.
        let mut counts = format!(
            "+{} added, {} changed, {} removed",
            since.added, since.changed, since.removed
        );
        if first > 0 {
            counts.push_str(&format!(
                ", {} read for the first time and kept as the baseline",
                plural(first, "thing", "things")
            ));
        }
        let mut unknown = Vec::new();
        if partial {
            unknown.push("removals unknown where a reading was partial");
        }
        if nothing {
            unknown.push("changes unknown where nothing was read");
        }
        let summary = if !finished && !watcher {
            "did not finish, changes unknown".to_string()
        } else if !unknown.is_empty() {
            format!("{counts}; {}", unknown.join(", "))
        } else if !events.is_empty() {
            counts
        } else {
            "no changes".to_string()
        };
        let summary = if sampled {
            "sample of running programs and their connections".to_string()
        } else if watcher {
            // A reading of some places names them; one of every place, too many to name, says
            // how many kinds it read.
            let kinds: Vec<String> = kinds_stmt
                .query_map(params![run_id, crate::watched::CONTENT], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let read = if kinds.len() <= KINDS_NAMED {
                kinds.join(", ")
            } else {
                format!("{} kinds of watched places", kinds.len())
            };
            format!("watcher's reading of {read}: {summary}")
        } else {
            summary
        };

        write!(
            out,
            "<details{}>\n<summary><span class=\"nowrap\">{}</span> · {}</summary>\n",
            if i == 0 && events.len() <= EVENTS_SHOWN_OPEN {
                " open"
            } else {
                ""
            },
            utc(*at),
            esc(&summary)
        )?;
        // The run's line, as the run printed it: what its readers' sources said in it, such as
        // why a server could not be opened, was cut piece by piece when the line was put
        // together (`report` in main.rs), and is never cut again, which could take the core's
        // words with it.
        if let Some(report) = report {
            writeln!(out, "<p class=\"muted mono\">{}</p>", esc_said(report))?;
        }
        if not_repeated > 0 {
            writeln!(
                out,
                "<p class=\"alert\">{} read before were not read in this run.</p>",
                plural(not_repeated as usize, "reading", "readings")
            )?;
        }
        if !not_full.is_empty() {
            out.push_str("<ul class=\"readings\">\n");
            for (scope, kind, completeness, reason, _) in &not_full {
                write!(
                    out,
                    "<li><span class=\"mono\">{}</span> · {} ",
                    esc(scope),
                    esc(kind)
                )?;
                badge(out, completeness, reason.as_deref())?;
                writeln!(
                    out,
                    " {}</li>",
                    esc_said(
                        &reason
                            .as_deref()
                            .map_or("no reason given".to_string(), said)
                    )
                )?;
            }
            out.push_str("</ul>\n");
        }
        if !events.is_empty() {
            out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
            thead(out, &["Change", "Component", "Where", "What", "Value"]);
            for e in &events {
                let entry = if e.first { "first reading" } else { &e.entry };
                write!(out, "<tr class=\"{}\">", esc(&e.entry))?;
                td(out, "", entry)?;
                td_component(out, &e.subject)?;
                td(out, "mono", component_place(&e.subject))?;
                td(out, "", what(&e.predicate))?;
                let value = match (&e.old, &e.new) {
                    (Some(o), Some(n)) => format!("{o} → {n}"),
                    (Some(v), None) | (None, Some(v)) => v.clone(),
                    (None, None) => String::new(),
                };
                td(out, "mono", &value)?;
                out.push_str("</tr>\n");
            }
            out.push_str("</tbody></table></div>\n");
        }
        out.push_str("</details>\n");
    }
    out.push_str("</section>\n");
    Ok(())
}

fn retracted(conn: &Connection, out: &mut String) -> Out {
    out.push_str("<section id=\"gone\">\n<h2>No longer there</h2>\n");
    type Row = (String, String, String, String, i64, Option<i64>, String);
    let rows: Vec<Row> = conn
        .prepare(
            // A fact of a kind no longer read was set aside, not found gone
            // (`lifecycle::retire`).
            "SELECT subject, predicate, object, reader, observed_at, retracted_at, source_ref
             FROM assertion a WHERE layer = 'retracted'
               AND NOT EXISTS (SELECT 1 FROM journal j
                               WHERE j.entry = 'retired' AND j.run_id = a.retracted_by
                                 AND j.reader = a.reader AND j.scope = a.scope
                                 AND j.kind = a.kind AND j.subject = a.subject
                                 AND j.predicate = a.predicate)
             ORDER BY retracted_at DESC, subject, predicate, object",
        )?
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    if rows.is_empty() {
        out.push_str("<p>Nothing has disappeared yet.</p>\n</section>\n");
        return Ok(());
    }
    write!(
        out,
        "<details>\n<summary>{} statements no longer made, newest first</summary>\n",
        rows.len()
    )?;
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    thead(
        out,
        &[
            "Component",
            "Where",
            "What",
            "Value",
            "Reader",
            "First seen",
            "Gone since",
            "Source",
        ],
    );
    for (subject, predicate, object, reader, seen, gone, source) in &rows {
        out.push_str("<tr>");
        td_component(out, subject)?;
        td(out, "mono", component_place(subject))?;
        td(out, "", what(predicate))?;
        td(out, "mono", object)?;
        td(out, "", reader)?;
        td(out, "nowrap", &utc(*seen))?;
        td(out, "nowrap", &utc_or(*gone, ""))?;
        td(out, "mono", source)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n</details>\n</section>\n");
    Ok(())
}

fn vocabulary(conn: &Connection, out: &mut String) -> Out {
    out.push_str("<section id=\"vocabulary\">\n<h2>Vocabulary</h2>\n<details>\n");
    out.push_str("<summary>The words the store uses: kinds of things, links between them, what readings look for and how a source knows</summary>\n");
    let tables: [(&str, &[&str], &str); 4] = [
        (
            "Kinds of things",
            &["Name", "Status"],
            "SELECT name, status FROM entity_type ORDER BY status = 'reserved', name",
        ),
        (
            "Links",
            &["Name", "Points to", "Status"],
            "SELECT name, COALESCE(object_kind, ''), status FROM predicate
             ORDER BY status = 'reserved', name",
        ),
        (
            "What readings look for",
            &["Name"],
            "SELECT name FROM coverage_kind ORDER BY name",
        ),
        (
            "Basis, strongest first",
            &["Name", "Strength"],
            "SELECT name, CAST(strength AS TEXT) FROM basis_kind ORDER BY strength",
        ),
    ];
    for (title, columns, sql) in tables {
        write!(
            out,
            "<h3>{title}</h3>\n<div class=\"scroll\"><table class=\"dense\">\n"
        )?;
        thead(out, columns);
        let mut stmt = conn.prepare(sql)?;
        let n = stmt.column_count();
        let rows = stmt.query_map([], |r| {
            (0..n)
                .map(|i| r.get::<_, String>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        for row in rows {
            out.push_str("<tr>");
            for cell in row? {
                td(out, "", &cell)?;
            }
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</details>\n</section>\n");
    Ok(())
}

const HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>What the store holds</title>
<style>
/* One stylesheet for every page, with the colours and measures of the design sheet. Its values
   are the custom properties below; a change of design is a change of these values.
   Five colour roles, each a macOS system colour, the same as the panel's:
   --now (red): needs the person now; the response layer said suspicious.
   --look (orange): to look at, not urgent; watched or read in part; could not be read; you can fix.
   --calm (green): watched, read in full, nothing to look at; the response layer said harmless.
   --link (blue): what opens something: links, counts that are links, the selected control.
   --quiet (grey): none here, not applicable, off, never checked.
   Colour is a mark (a dot, a glyph, one word, a thin tint behind the state band), never a filled
   row and never body text, and it always stands beside the word that says the same. A dot or a
   glyph takes the hue itself; a word takes its -ink variant, dark enough to read on the page. */
:root {
  color-scheme: light dark;
  --now: #FF3B30; --look: #FF9500; --calm: #28CD41; --link: #0066CC; --quiet: #8E8E93;
  --now-ink: #D70015; --look-ink: #C93400; --calm-ink: #248A3D;
  --bg: #FFFFFF; --fill: #F5F5F7; --t1: #1D1D1F; --t2: #6E6E73; --t3: #AEAEB2; --sep: #E5E5EA;
  --grid: #D2D2D7; --bar: var(--link); --on: #FFFFFF;
  --font: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro", "Helvetica Neue", Helvetica, Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace;
  /* Type: size / line height. */
  --title: 600 22px/28px var(--font); --heading: 600 15px/20px var(--font); --body: 13px/20px var(--font);
  --caption: 12px/16px var(--font); --data: 12px/20px var(--mono); --number: 600 22px/28px var(--font);
  /* Measures, every one a multiple of 4. */
  --page: 880px; --gutter: 40px; --section: 40px; --radius: 12px; --radius-row: 8px; --radius-tab: 6px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --now: #FF453A; --look: #FF9F0A; --calm: #32D74B; --link: #2997FF; --quiet: #98989D;
    --now-ink: #FF6961; --look-ink: #FFB340; --calm-ink: #30DB5B;
    --bg: #1C1C1E; --fill: #2C2C2E; --t1: #F5F5F7; --t2: #98989D; --t3: #636366; --sep: #38383A;
    --grid: #48484A;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--t1); font: var(--body); }
main { max-width: calc(var(--page) + 2 * var(--gutter)); margin: 0 auto; padding: 32px var(--gutter) 40px; }
h1 { font: var(--title); margin: 0 0 4px; }
h2 { font: var(--heading); margin: var(--section) 0 8px; }
h3 { font: 600 13px/20px var(--font); margin: 16px 0 4px; }
h4 { font: 600 12px/16px var(--font); margin: 12px 0 4px; }
p { margin: 8px 0; }
a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }
a:focus-visible, summary:focus-visible { outline: 2px solid var(--link); outline-offset: 2px; border-radius: 4px; }
.meta { color: var(--t2); font: var(--caption); margin: 0; overflow-wrap: anywhere; }
.muted, .sec, .quiet, .t2 { color: var(--t2); }
.mono, code, .said { font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
/* Text from the Mac or a source (`secrets::Name::html`): isolated, so it cannot reorder the words around it. */
bdi.src { unicode-bidi: isolate; overflow-wrap: anywhere; }
.nowrap { white-space: nowrap; }
.num { font-variant-numeric: tabular-nums; }
.hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
nav { margin-bottom: 12px; }
header { margin-bottom: 8px; }

/* Tables of the pages of details. */
.scroll { overflow-x: auto; margin: 4px 0; }
/* A table wider than the page scrolls in its box; its scroll bar stays drawn, so a column past the
   right edge reads as more to scroll to and not as cut off. */
.scroll::-webkit-scrollbar { height: 8px; }
.scroll::-webkit-scrollbar-thumb { background: var(--t3); border-radius: 4px; }
table { border-collapse: collapse; width: 100%; font: var(--body); }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--sep); vertical-align: top; }
th { color: var(--t2); font: var(--caption); white-space: nowrap; }
table.dense th, table.dense td { padding: 4px 8px; }
/* One rule for every table: a column of short data is as wide as its content and keeps it on one
   line; prose takes the rest and wraps, no column of it narrower than 12 characters; a table that
   cannot fit scrolls in its own box (.scroll), never the page.
   - A time (td.nowrap, by .nowrap above) never wraps.
   - Data (td.mono) wraps only between the names of a list, and breaks inside a name only past 36
     characters, so a long path neither stays on one line nor squeezes the prose beside it.
   - Words (a plain td) wrap, and a long path or id among them breaks rather than widening the
     column. */
td.mono { white-space: normal; overflow-wrap: break-word; max-width: 36ch; }
td:not(.mono):not(.nowrap) { min-width: 12ch; overflow-wrap: anywhere; }
tr.bad td { font-weight: 600; }
tr.removed td:first-child, tr.changed td:first-child { color: var(--t2); }

/* Marks and notes of the pages of details: words, never a colour. */
.badge { display: inline-block; padding: 0 8px; border-radius: 999px; font: 600 12px/20px var(--font); white-space: nowrap; border: 1px solid var(--sep); }
.badge.notify { font-weight: 400; }
.alert, .ok { border-left: 2px solid var(--t3); padding: 8px 12px; overflow-wrap: anywhere; background: var(--fill); }
.alert { font-weight: 600; }
details { margin: 8px 0; }
summary { cursor: pointer; padding: 4px 0; overflow-wrap: anywhere; }
details.machine { border-top: 1px solid var(--sep); margin: 0; padding: 4px 0; }
details.machine > .inner { padding: 0 0 8px 12px; }
details.sub { margin: 4px 0; }
ul.readings { margin: 4px 0; padding-left: 16px; font: var(--data); }
ul.readings li { margin: 0; overflow-wrap: anywhere; }
ul.counts { list-style: none; padding: 0; }
ul.counts li { margin: 4px 0; }
ul.rules { margin: 4px 0 12px; padding-left: 16px; }
ul.rules li { margin: 4px 0; }
article.item { border-top: 1px solid var(--sep); padding: 12px 0; margin: 0; }
article.item h3 { margin: 0 0 4px; }
.advice { color: var(--t2); }
.scale { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(240px, 100%), 1fr)); gap: 24px; margin: 16px 0 8px; }
.scale p { margin: 0; display: flex; flex-direction: column; gap: 4px; }
.scale .num { font: var(--number); }
article.rule { border-top: 1px solid var(--sep); padding: 12px 0; }
article.rule h4 { font: 600 13px/20px var(--font); margin: 0 0 4px; display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 12px; }
.chip { font: var(--caption); color: var(--t2); }
article.rule .missing { margin: 4px 0; }
article.rule details { margin: 0; }
article.rule summary { color: var(--t2); list-style: none; display: flex; gap: 8px; }
article.rule summary::-webkit-details-marker { display: none; }
article.rule summary::before { content: "\25B8"; flex: none; color: var(--t3); }
article.rule details[open] summary::before { content: "\25BE"; }
article.rule summary .desc { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
article.rule details[open] summary .desc { display: block; }
article.rule ul.about { margin: 4px 0 0; padding-left: 16px; }
article.rule ul.about li { margin: 4px 0; overflow-wrap: anywhere; }
footer.licence { margin-top: 32px; }

/* The report: src/pages.rs and src/happens.rs. */
.summary section { margin-top: var(--section); }
.wsh { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 12px; padding-bottom: 8px; border-bottom: 1px solid var(--sep); min-height: 37px; }
.wsh h2 { margin: 0; }
.wsh .n { font: var(--caption); color: var(--t2); }
.wsh .tabs { margin-left: auto; }

/* The state band. */
#this-mac { margin-top: 0; display: grid; grid-template-columns: 40px minmax(0, 1fr); column-gap: 16px; align-items: center;
  padding: 20px 24px; background: var(--fill); border-radius: var(--radius); }
#this-mac .glyph { width: 40px; height: 40px; }
/* A thin tint of the state's colour behind the band, taken from its glyph; grey stays grey. */
#this-mac:has(> .glyph.now) { background: color-mix(in srgb, var(--now) 9%, var(--fill)); }
#this-mac:has(> .glyph.look) { background: color-mix(in srgb, var(--look) 11%, var(--fill)); }
#this-mac:has(> .glyph.calm) { background: color-mix(in srgb, var(--calm) 10%, var(--fill)); }
#this-mac h1 { margin: 0; }
#this-mac .sub { font: var(--caption); color: var(--t2); margin: 4px 0 0; overflow-wrap: anywhere; }
/* A fault, a block of its own: the core's words in the band's main colour, what the source said
   as data, its command, and what the person can do on a line under them. */
#this-mac .fault { color: var(--t1); margin-top: 8px; }
#this-mac .fault .advice { display: block; }
#this-mac .cmd { white-space: nowrap; }

/* Findings: the tabs, a group for each, one row per thing that opens in place. */
.tabs { display: inline-flex; padding: 2px; background: var(--fill); border-radius: var(--radius-row); }
.tabs a { height: 24px; display: inline-flex; align-items: center; gap: 6px; padding: 0 12px; border-radius: var(--radius-tab);
  font: 13px/24px var(--font); color: var(--t1); }
.tabs a:hover { text-decoration: none; }
.tabs .tn { color: var(--t2); font-variant-numeric: tabular-nums; }
.findings:not(:has(#answered:target, #all:target)) #open, #answered:target, #all:target {
  background: var(--bg); box-shadow: 0 0 0 .5px rgba(0, 0, 0, .12), 0 1px 2px rgba(0, 0, 0, .10); font-weight: 600; }
.findings:not(:has(#answered:target, #all:target, .fr.answered:not(.open):target, .fr.answered:not(.open) :target)) :is(.fr, .empty, .more, .fg):not(.open) { display: none; }
.findings:has(#answered:target) :is(.fr, .empty, .more, .fg):not(.answered) { display: none; }
.fg { font: 600 12px/16px var(--font); color: var(--t2); padding: 16px 12px 8px; margin: 0; }
.fg.open { color: var(--look-ink); }
.fg.now { color: var(--now-ink); }
/* Seen holds a time, or a date and a time: one line, as wide as "2026-11-13 14:37" in its digits. */
.fh, .fr > summary { display: grid; grid-template-columns: minmax(0, 1fr) 240px 96px 16ch 16px; column-gap: 12px; align-items: center;
  min-height: 40px; padding: 0 12px; border-bottom: 1px solid var(--sep); }
/* Each row's dot in its group's colour, in the first cell's padding: red needs you now, orange to
   look at, grey answered. */
.fr > summary { position: relative; }
.fr > summary::before { content: ""; position: absolute; left: 2px; top: 50%; width: 6px; height: 6px; margin-top: -3px;
  border-radius: 50%; background: var(--quiet); }
.fr.open > summary::before { background: var(--look); }
.fr.urgent > summary::before { background: var(--now); }
.fr.suspicious .fv { color: var(--now-ink); }
.fr.harmless .fv { color: var(--calm-ink); }
.fh { min-height: 32px; font: var(--caption); color: var(--t2); }
.fh .fs { text-align: right; }
.fr { margin: 0; }
.fr > summary { list-style: none; cursor: pointer; }
.fr > summary::-webkit-details-marker { display: none; }
.fr > summary:hover { background: var(--fill); }
.fr[open] > summary { background: var(--fill); border-bottom: 0; border-radius: var(--radius-row) var(--radius-row) 0 0; }
.fr .fw { font: var(--data); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.fr .fk, .fr .fs { color: var(--t2); }
.fr .fs { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.fr .fv .none { color: var(--t3); }
/* Whose word the cell is: said to a screen reader always, shown where the column has no header. */
.fr .fv .src { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
.fr .fch { color: var(--t3); justify-self: end; }
.fr .fch::before { content: "\203A"; }
.fr[open] .fch::before { content: "\2039"; display: inline-block; transform: rotate(-90deg); }
.fr .ans { display: block; font: var(--caption); color: var(--t2); }
.fx { background: var(--fill); border-radius: 0 0 var(--radius-row) var(--radius-row); padding: 8px 12px 20px 48px; margin-bottom: 4px;
  display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); column-gap: 32px; row-gap: 16px; }
.fx > * { min-width: 0; }
.fx .also { grid-column: 1 / -1; border-top: 1px solid var(--sep); padding-top: 12px;
  display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); column-gap: 32px; row-gap: 16px; }
.fx .also > .wsh2 { grid-column: 1 / -1; }
dl.facts { display: grid; grid-template-columns: 96px minmax(0, 1fr); column-gap: 12px; row-gap: 4px; margin: 0; align-content: start; }
dl.facts dt { font: 12px/20px var(--font); color: var(--t2); }
dl.facts dd { margin: 0; font: var(--data); overflow-wrap: anywhere; min-width: 0; }
dl.facts dd .w { font: 12px/20px var(--font); }
.arg { background: var(--bg); border-radius: 4px; padding: 0 4px; }
.wsh2 { font: 600 12px/16px var(--font); color: var(--t2); margin: 0 0 8px; }
.voices { display: flex; flex-direction: column; gap: 12px; }
.voice .vn { font: var(--caption); color: var(--t2); }
.voice .vs { font: var(--body); color: var(--t1); }
.voice .vd { font: var(--caption); color: var(--t2); }
.quote { margin: 4px 0 0; padding-left: 8px; border-left: 2px solid var(--t3); font: var(--data); white-space: pre-wrap; overflow-wrap: anywhere; }
.fxb { grid-column: 1 / -1; display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px 24px; font: var(--caption); color: var(--t2);
  padding-top: 12px; border-top: 1px solid var(--sep); }
.fxb .mono { color: var(--t1); }
/* The command and its copy button never part; "For your agent" may wrap away from them. */
.fxb .cmd { margin-left: 3px; white-space: nowrap; }
/* The copy button beside it (src/happens.js): two overlapping squares in the line's height, no
   box; a check mark for a moment once it copied. */
.copy { position: relative; width: 14px; height: 16px; margin: 0 0 0 4px; padding: 0; border: 0; background: none;
  color: var(--t2); cursor: pointer; vertical-align: top; border-radius: 4px; }
.copy:hover { color: var(--t1); }
.copy:focus-visible { outline: 2px solid var(--link); outline-offset: 2px; }
.copy::before, .copy::after { content: ""; position: absolute; width: 8px; height: 8px; border: 1.2px solid currentColor; border-radius: 2px; }
.copy::before { left: 1px; top: 2px; }
.copy::after { left: 4px; top: 5px; background: var(--fill); }
.copy.done { color: var(--calm-ink); }
.copy.done::before { display: none; }
.copy.done::after { left: 4px; top: 2px; width: 5px; height: 9px; border-width: 0 1.5px 1.5px 0; border-radius: 0; background: none; transform: rotate(45deg); }
.empty, .more { padding: 24px 12px; color: var(--t2); margin: 0; border-bottom: 1px solid var(--sep); }
.more { padding: 12px; }
#you-can-fix .empty { border-bottom: 0; }
/* Its count in orange while there is something to fix. */
#you-can-fix:has(.fixg) .wsh .n { color: var(--look-ink); }

/* What is watched: a row per kind of place, grouped; the state is coverage alone. */
.wt { overflow-x: auto; }
.wr { display: grid; grid-template-columns: minmax(0, 1fr) 152px 96px 240px 64px; column-gap: 16px; align-items: start;
  padding: 8px 12px; border-bottom: 1px solid var(--sep); min-height: 36px; }
.wr.wh { font: var(--caption); color: var(--t2); padding-top: 12px; }
.wr .wn { text-align: right; font-variant-numeric: tabular-nums; }
.wr .wl { color: var(--t2); text-align: right; font-variant-numeric: tabular-nums; }
.wr .wc { color: var(--t2); }
.wg { font: 600 12px/16px var(--font); color: var(--t2); padding: 16px 12px 8px; margin: 0; }
/* Green read; orange hollow a fault; grey none here or a count; grey hollow never checked. */
.dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: var(--quiet); vertical-align: 1px; margin-right: 4px; }
.dot.calm { background: var(--calm); }
.dot.off { background: transparent; box-shadow: inset 0 0 0 1px var(--quiet); }
.dot.off.look { box-shadow: inset 0 0 0 1.5px var(--look); }
.nj { display: block; padding: 12px; margin: 0; }

/* What this version does not read here, src/not_read_here.rs: collapsed, its heading the control. */
#not-read-here details { margin: 0; }
#not-read-here summary { list-style: none; }
#not-read-here summary::-webkit-details-marker { display: none; }
#not-read-here summary::before { content: "\25B8"; color: var(--t3); }
#not-read-here details[open] summary::before { content: "\25BE"; }
ul.limits { list-style: none; padding: 0; margin: 0; }
ul.limits li { padding: 8px 12px; border-bottom: 1px solid var(--sep); overflow-wrap: anywhere; }
ul.limits .advice { display: block; }

/* As it happens: src/happens.rs. */
#as-it-happens .live { margin-left: auto; font: var(--caption); color: var(--t2); font-variant-numeric: tabular-nums; }
#as-it-happens .first { padding: 16px 12px 0; color: var(--t2); margin: 0; }
#as-it-happens .first strong { color: var(--t1); font-weight: 600; }
#as-it-happens .first.note { font: var(--caption); padding-top: 4px; }
#as-it-happens[data-moved="yes"] .stats, #as-it-happens[data-moved="yes"] .matched { opacity: .5; }
#as-it-happens [hidden] { display: none; }
.stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); column-gap: 24px; row-gap: 16px; padding: 16px 12px 8px; }
.stat { display: flex; flex-direction: column; min-width: 0; }
.stat .st, .stat .ss { font: var(--caption); color: var(--t2); }
.stat .ss { margin-top: 4px; max-width: 260px; }
.stat .sv { font: var(--number); font-variant-numeric: tabular-nums; }
.stat svg.hours { display: block; width: 240px; max-width: 100%; height: 32px; margin-top: 8px; }
.rr { display: grid; grid-template-columns: minmax(0, 1fr) 136px 88px 136px; column-gap: 16px; align-items: center; min-height: 36px;
  padding: 0 12px; border-bottom: 1px solid var(--sep); }
.rr.rh { min-height: 32px; font: var(--caption); color: var(--t2); }
.rr .rt { overflow-wrap: anywhere; min-width: 0; }
.rr .rc { text-align: right; font-variant-numeric: tabular-nums; }
.rr .rl, .rr .rs { color: var(--t2); }
.matched .none, .matched .all { color: var(--t2); padding: 12px; margin: 0; }
.matched { margin-top: 16px; }
.matched .sh { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 12px; padding: 16px 12px 4px; }
.matched .sh h4 { font: 600 12px/16px var(--font); color: var(--t2); margin: 0; }
.matched .sh .n { font: var(--caption); color: var(--t2); }
.wsh3 { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 24px; padding: 24px 12px 12px; }
.wsh3 h3 { font: 600 12px/16px var(--font); color: var(--t2); margin: 0; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 20px; list-style: none; padding: 0; margin: 0; font: var(--caption); color: var(--t2); }
.legend li { display: flex; align-items: center; gap: 6px; }
.tactics { display: flex; flex-direction: column; gap: 4px; padding: 0 12px; }
.tactic { display: grid; grid-template-columns: 168px minmax(0, 1fr); column-gap: 16px; align-items: center; min-height: 20px; }
.tactic .tn2 { font: var(--caption); color: var(--t2); }
.sq { display: flex; flex-wrap: wrap; gap: 4px; }
/* A technique: watched and quiet a thin green tint; matched an orange tint in three steps by its
   matches (the legend shows the middle one); a finding raised on it orange with a darker edge, red
   when the finding needs the person now. */
.m { display: block; flex: none; width: 12px; height: 12px; border-radius: 2px; background: var(--grid); }
.m.calm { background: color-mix(in srgb, var(--calm) 22%, var(--bg)); }
.m.hit { background: color-mix(in srgb, var(--look) 50%, var(--bg)); }
.m.hit.s1 { background: color-mix(in srgb, var(--look) 28%, var(--bg)); }
.m.hit.s3 { background: color-mix(in srgb, var(--look) 75%, var(--bg)); }
.m.look { background: var(--look); box-shadow: inset 0 0 0 1.5px var(--look-ink); }
.m.look[data-now] { background: var(--now); box-shadow: none; }
.covers > .meta { margin: 12px 12px 0; }
/* The pop-up over a technique's square (src/happens.js): its id and name, MITRE's first sentence
   of what it is, and its state. */
.m:focus-visible { outline: 2px solid var(--link); outline-offset: 1px; }
.tip { position: absolute; z-index: 1; max-width: min(320px, calc(100vw - 32px)); padding: 8px 12px; background: var(--bg);
  border: 1px solid var(--sep); border-radius: var(--radius-row); box-shadow: 0 1px 2px rgba(0, 0, 0, .10);
  font: var(--caption); color: var(--t1); pointer-events: none; }
.tip span { display: block; overflow-wrap: anywhere; }
.tip .tt { font-weight: 600; }
.tip .td { margin-top: 4px; }
.tip .ts { margin-top: 4px; color: var(--t2); }

/* You can fix. */
.fixg { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); column-gap: 32px; row-gap: 24px; padding: 16px 12px 0; }
.fixc { min-width: 0; }
.fixc .fct { font: 600 13px/20px var(--font); margin: 0; }
.fixc ul { list-style: none; margin: 8px 0; padding: 0; font: var(--data); }
.fixc li { overflow-wrap: anywhere; }
.fixc .fad { color: var(--t2); margin: 0; }
footer.links { display: flex; flex-wrap: wrap; gap: 8px 24px; margin-top: var(--section); padding: 16px 12px 0; border-top: 1px solid var(--sep); }
.wfoot { font: var(--caption); color: var(--t2); padding: 8px 12px 0; margin: 0; }

@media (max-width: 760px) {
  main { padding: 16px 16px 40px; }
  #this-mac { padding: 16px; }
  .fh { display: none; }
  .fr > summary { grid-template-columns: minmax(0, 1fr) auto 16px; row-gap: 0; padding: 8px 12px; }
  .fr > summary .fw { grid-column: 1 / -1; white-space: normal; overflow-wrap: anywhere; }
  .fr > summary .fk { grid-column: 1 / -1; }
  .fr > summary::before { top: 15px; margin-top: 0; }
  .fr .fv .src { position: static; width: auto; height: auto; overflow: visible; clip-path: none; color: var(--t2); }  .fx, .fx .also { grid-template-columns: minmax(0, 1fr); padding-left: 12px; }
  .wr.wh { display: none; }
  .wr { grid-template-columns: minmax(0, 1fr) auto; row-gap: 0; }
  .wr .wh2, .wr .wc { grid-column: 1 / -1; }
  .wr .wn { grid-row: 1; grid-column: 2; }
  .wr .wl { display: none; }
  .stats, .fixg { grid-template-columns: minmax(0, 1fr); }
  .rr { grid-template-columns: minmax(0, 1fr) auto; }
  .rr .rl, .rr.rh { display: none; }
  .tactic { grid-template-columns: minmax(0, 1fr); }
}
</style>
</head>
<body>
<main>
"#;

#[cfg(test)]
mod tests {
    use super::{esc, esc_said, shown, utc};

    #[test]
    fn the_last_run_finished_is_the_one_the_journal_wrote_last_even_after_the_clock_was_set_back() {
        let dir = std::env::temp_dir().join(format!("immunity-view-head-{}", std::process::id()));
        crate::common::remove(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let (ahead, latest) = (1_800_086_400, 1_800_000_000);
        crate::store::journal_note(&conn, ahead, "run-1", "run_finished", "").unwrap();
        crate::store::journal_note(&conn, latest, "run-2", "run_finished", "").unwrap();
        let mut out = String::new();
        super::header(&conn, &mut out, "store", latest + 60).unwrap();
        assert!(
            out.contains(&format!("last run finished {}", utc(latest))),
            "{out}"
        );
        drop(conn);
        crate::common::remove(&dir);
    }

    #[test]
    fn a_time_ahead_of_the_clock_is_said_to_be_ahead_and_never_given_an_age() {
        let now = 1_800_000_000;
        let ahead = now + crate::store::AHEAD_ALLOWED + 1;
        assert_eq!(
            super::utc_age(ahead, now),
            format!("{} · ahead of this Mac's clock", utc(ahead))
        );
        assert_eq!(
            super::utc_age(now - 86_400, now),
            format!("{} · 1 day ago", utc(now - 86_400))
        );
        assert_eq!(
            super::utc_age(now - 3 * 86_400, now),
            format!("{} · 3 days ago", utc(now - 3 * 86_400))
        );
    }

    #[test]
    fn a_name_on_a_page_never_reads_as_a_mark_and_a_mark_the_core_made_stays_one() {
        // A page writes every name through `esc`: a file named like a mark shows its backslash
        // as a source's. A name the contract gave, already written so, is kept as it is. Cut text
        // goes through `esc_said`, where the core's marks stay bare.
        let forged = "/Users/example/\\cut{gitleaks:github-pat 40}";
        assert_eq!(
            esc(forged),
            "/Users/example/\\u{5c}cut{gitleaks:github-pat 40}"
        );
        assert_eq!(
            esc("a\\u{5c}b \\u{202e} \\u{} \\u{1234567}"),
            "a\\u{5c}b \\u{202e} \\u{5c}u{} \\u{5c}u{1234567}"
        );
        assert_eq!(esc_said(forged), forged);
        assert_eq!(esc("<a>"), esc_said("<a>"));
    }

    #[test]
    fn every_character_that_could_reorder_or_hide_text_is_shown_escaped() {
        // A name from a source is partly written by an attacker. Printed raw, a direction
        // control reorders the rest of the line and an invisible character hides text.
        let hidden = [
            '\u{0}',
            '\u{9}',
            '\u{A}',
            '\u{1B}',
            '\u{7F}',
            '\u{85}',
            '\u{9F}',
            '\u{AD}',
            '\u{600}',
            '\u{605}',
            '\u{61C}',
            '\u{6DD}',
            '\u{70F}',
            '\u{890}',
            '\u{891}',
            '\u{8E2}',
            '\u{180E}',
            '\u{200B}',
            '\u{200F}',
            '\u{2028}',
            '\u{2029}',
            '\u{202E}',
            '\u{2060}',
            '\u{2064}',
            '\u{2066}',
            '\u{206F}',
            '\u{FEFF}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{110BD}',
            '\u{110CD}',
            '\u{13430}',
            '\u{1343F}',
            '\u{1BCA0}',
            '\u{1BCA3}',
            '\u{1D173}',
            '\u{1D17A}',
            '\u{E0001}',
            '\u{E0020}',
            '\u{E007F}',
            // Default-ignorable: drawn as nothing, though not format characters.
            '\u{34F}',
            '\u{115F}',
            '\u{1160}',
            '\u{3164}',
            '\u{FE00}',
            '\u{FE0F}',
            '\u{FFA0}',
            '\u{E0100}',
            '\u{E01EF}',
        ];
        for c in hidden {
            let escaped: String = c.escape_unicode().collect();
            let text = format!("a{c}b");
            assert_eq!(shown(&text), format!("a{escaped}b"), "{escaped}");
            assert_eq!(esc(&text), format!("a{escaped}b"), "{escaped}");
        }
        // A version carrying variation selectors is not shown as clean text.
        assert_eq!(shown("1.2.3\u{FE0F}\u{E0100}"), "1.2.3\\u{fe0f}\\u{e0100}");
        // Everything else is shown as it is, names in any script included.
        let plain = "web-1 сервер 東京 café ✓ \u{2027}\u{2030}\u{FFFC} Ελλάδα مرحبا שלום \
                     नमस्ते 한국어 ไทย ጤና Ꭰ 𝔘 😀";
        assert_eq!(shown(plain), plain);
        assert_eq!(esc(plain), plain);
    }

    #[test]
    fn times_are_shown_as_utc_calendar_dates() {
        // The owner reads every time on the page; a wrong date misleads silently.
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(utc(1_731_196_800), "2024-11-10 00:00 UTC");
        assert_eq!(utc(4_107_542_340), "2100-02-28 23:59 UTC");
    }

    #[test]
    fn the_changes_page_says_the_same_of_every_run_it_lists_after_a_fold() {
        // The fold keeps every reading of the runs the page lists (`store::listed_runs`), a
        // watcher's readings before the first full check among them: a run that could not read
        // a kind still says so after older readings were folded.
        use crate::store::{
            Cause, Event, Gap, Reading, journal_event, journal_note, put_coverage, put_entity,
        };
        use crate::watched::{AUTOSTART_KIND, PROFILE_KIND, READER};
        let dir = std::env::temp_dir().join(format!(
            "immunity-view-fold-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _removed = crate::common::Scratch::at(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let mut conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let mac = "machine:mac";
        // `journaled`: a reading the page lists, that recorded a change; `full`: a full run.
        let write = |conn: &mut rusqlite::Connection, i: i64, journaled: bool, full: bool| {
            let at = 1_900_000_000 + i * 60;
            let run_id = if full {
                format!("{at}-000000000")
            } else {
                format!("{}{at}-000000000", crate::watch::RUN_PREFIX)
            };
            if full {
                journal_note(conn, at, &run_id, "run_started", "").unwrap();
            }
            let tx = conn.transaction().unwrap();
            put_entity(&tx, mac).unwrap();
            let r = |kind| Reading {
                reader: READER,
                scope: mac,
                kind,
                run_id: &run_id,
                at,
                observed_at: at,
            };
            // The shell profiles could not be read; the launch agents were.
            let denied = Gap::of(Cause::Failed);
            put_coverage(&tx, &r(PROFILE_KIND), "none", Some("denied"), &denied).unwrap();
            put_coverage(&tx, &r(AUTOSTART_KIND), "full", None, &Gap::default()).unwrap();
            if journaled {
                let e = Event {
                    kind: "changed",
                    subject: format!("file:{mac}/Library/LaunchAgents/org.example.plist"),
                    predicate: "has_content".to_string(),
                    old: Some(format!("a{i}")),
                    new: Some(format!("b{i}")),
                };
                journal_event(&tx, &r(AUTOSTART_KIND), &e, None).unwrap();
            }
            if full {
                journal_note(&tx, at, &run_id, "report", "").unwrap();
                journal_note(&tx, at, &run_id, "run_finished", "").unwrap();
            }
            tx.commit().unwrap();
        };
        // Readings that changed nothing, which no page lists; then five that the page lists,
        // then three full checks.
        for i in 0..10 {
            write(&mut conn, i, false, false);
        }
        for i in 10..15 {
            write(&mut conn, i, true, false);
        }
        for i in 15..18 {
            write(&mut conn, i, true, true);
        }
        let page = |conn: &rusqlite::Connection| {
            let mut out = String::new();
            super::changes(conn, &mut out).unwrap();
            out
        };
        let before = page(&conn);
        let unknown = "changes unknown where nothing was read";
        assert_eq!(before.matches(unknown).count(), 8);
        // A watcher's reading names the kinds it read, not every watched place.
        let named = esc(&format!(
            "watcher's reading of {AUTOSTART_KIND}, {PROFILE_KIND}:"
        ));
        assert_eq!(before.matches(&named).count(), 5);
        let folded = crate::store::fold(&conn).unwrap();
        let after = page(&conn);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(folded.removed, 16);
        assert_eq!(after, before);
    }

    #[test]
    fn a_secret_in_what_a_reader_s_source_said_reaches_no_page_and_no_form_of_the_status_and_is_marked_cut()
     {
        // A reader's reason is its source's words, which can hold a token: a tool that echoes a
        // URL, a server that repeats a command. Wherever it is printed (the run's line on the
        // page of changes, why a kind of watched place was not read in full in each form of the
        // status, and the hint of "not read in full" on the summary) it is cut, marked as every
        // cut is, and the token is in no byte of any page or answer.
        use crate::store::{Cause, Gap, Reading, journal_note, put_coverage, put_entity};
        use crate::watched::{AUTOSTART_KIND, PROFILE, PROFILE_KIND, READER};
        use prost::Message;
        let scratch = crate::common::Scratch::new("view-reason-cut");
        let dir = scratch.0.clone();
        let store = dir.join("store.db");
        let mut conn = crate::store::open_or_make(&store).unwrap();
        // Invented, of a kind the patterns know, and put together so none stands in the file.
        let token = format!(
            "{}{}",
            ["gh", "p_"].concat(),
            "Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS2aE7u"
        );
        let mark = crate::secrets::mark("gitleaks:github-pat", 40);
        let said = format!("a tool answered: fetch https://example.invalid/?t={token} refused");
        let (mac, server) = ("machine:mac", "machine:db-1");
        let at = 1_900_000_000;
        let run_id = format!("{at}-000000000");
        journal_note(&conn, at, &run_id, "run_started", "").unwrap();
        let tx = conn.transaction().unwrap();
        put_entity(&tx, mac).unwrap();
        put_entity(&tx, server).unwrap();
        let r = |reader, scope, kind| Reading {
            reader,
            scope,
            kind,
            run_id: &run_id,
            at,
            observed_at: at,
        };
        let failed = Gap::of(Cause::Failed);
        put_coverage(
            &tx,
            &r(READER, mac, PROFILE_KIND),
            "none",
            Some(&said),
            &failed,
        )
        .unwrap();
        put_coverage(
            &tx,
            &r(READER, mac, AUTOSTART_KIND),
            "full",
            None,
            &Gap::default(),
        )
        .unwrap();
        let visit = r(crate::servers::READER, server, crate::servers::VISIT);
        put_coverage(&tx, &visit, "none", Some(&said), &failed).unwrap();
        // A watched file whose content was not read, and a project on this Mac whose lockfiles
        // were not read, each with the same words.
        let (file, checkout) = ("file:machine:mac/.zshrc", "checkout:machine:mac/dev/site");
        put_entity(&tx, file).unwrap();
        put_entity(&tx, checkout).unwrap();
        for (subject, predicate, object, reader, scope, kind) in [
            (file, "watched_as", PROFILE, READER, mac, PROFILE_KIND),
            (
                checkout,
                "located_on",
                mac,
                crate::checkouts::READER,
                mac,
                crate::checkouts::KIND,
            ),
        ] {
            tx.execute(
                "INSERT INTO assertion (layer, subject, predicate, object, reader, scope, kind,
                                        source_ref, basis, observed_at, run_id)
                 VALUES ('live', ?1, ?2, ?3, ?4, ?5, ?6, 'invented:1', 'observed', ?7, ?8)",
                rusqlite::params![subject, predicate, object, reader, scope, kind, at, run_id],
            )
            .unwrap();
        }
        let content = r(READER, file, crate::watched::CONTENT);
        put_coverage(&tx, &content, "none", Some(&said), &failed).unwrap();
        let lockfiles = r(crate::lockfiles::READER, checkout, crate::lockfiles::KIND);
        put_coverage(&tx, &lockfiles, "none", Some(&said), &failed).unwrap();
        // The other places the store keeps a source's words: a reading of installed software,
        // downloads of the catalogue and of a feed that failed, and a reading of the event level
        // that failed, with why the cap of its log could not be read.
        let installed = r(crate::integrity::READER, mac, crate::integrity::BUNDLES);
        put_coverage(&tx, &installed, "none", Some(&said), &failed).unwrap();
        let download = crate::threats::Reading {
            outcome: "failed",
            reason: Some(said.clone()),
            ..Default::default()
        };
        crate::threats::put_reading(&tx, &run_id, at, &download).unwrap();
        tx.execute(
            "INSERT INTO feed_reading (source, run_id, at, outcome, reason)
             VALUES (?1, ?2, ?3, 'failed', ?4)",
            rusqlite::params![crate::osv::FEEDS[0].source, run_id, at, said],
        )
        .unwrap();
        // What the collector printed, as the store keeps it: a source's backslash as `\u{5c}`.
        let collector = "the log said \\u{5c}n";
        tx.execute(
            "INSERT INTO event_level (id, read_at, state, reason, said_by, said)
             VALUES (1, ?1, ?2, ?3, 'scripts', ?4)",
            rusqlite::params![at, crate::events::FAILING, said, collector],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO event_cap (id, bytes, why) VALUES (1, NULL, ?1)",
            [&said],
        )
        .unwrap();
        // The run's line, as a run writes it: its readers' reasons, each cut, inside its own
        // words.
        let line = format!(
            "1 reader. db-1 was never read; {}",
            crate::sweep::failed_visit(at, &said)
        );
        assert!(line.contains(&mark) && !line.contains(&token), "{line}");
        journal_note(&tx, at, &run_id, "report", &line).unwrap();
        journal_note(&tx, at + 1, &run_id, "run_finished", "").unwrap();
        tx.commit().unwrap();

        let now = at + 60;
        let st = crate::status::state(&conn, &dir, now).unwrap();
        let m = crate::status::message(Some(&conn), Some(&st), false, &store, now).unwrap();
        let kind = m
            .watched
            .as_ref()
            .and_then(|w| w.kinds.iter().find(|k| k.kind == PROFILE))
            .unwrap_or_else(|| panic!("{m:#?}"));
        let reason = kind.reason_text.as_deref().unwrap_or_default();
        assert!(
            reason.contains(&mark)
                && reason.starts_with("a tool answered: ")
                && !reason.contains(&token),
            "{reason}"
        );
        // Every other field the status gives such words in holds them, cut.
        let cut = |field: &str, said: Option<&str>| {
            let said = said.unwrap_or_else(|| panic!("{field} is absent: {m:#?}"));
            assert!(
                said.contains(&mark) && !said.contains(&token),
                "{field}: {said}"
            );
        };
        let threats = m.threats.as_ref().unwrap();
        cut("threats.reason_text", threats.reason_text.as_deref());
        let feeds = &m.vulnerability_data.as_ref().unwrap().feeds;
        let feed = feeds
            .iter()
            .find(|f| f.source == crate::osv::FEEDS[0].source);
        cut(
            "vulnerability_data.feeds.reason_text",
            feed.and_then(|f| f.reason_text.as_deref()),
        );
        let installed = &m.integrity.as_ref().unwrap().readings;
        cut(
            "integrity.readings.reason_text",
            installed.first().and_then(|r| r.reason_text.as_deref()),
        );
        let level = m.event_level.as_ref().unwrap();
        cut("event_level.reason_text", level.reason_text.as_deref());
        cut(
            "event_level.log_cap_reason_text",
            level.log_cap_reason_text.as_deref(),
        );
        let download = m.not_covered.iter().find(|u| {
            u.value_text
                .as_deref()
                .is_some_and(|v| v.contains("a tool answered"))
        });
        cut(
            "not_covered.value_text",
            download.and_then(|u| u.value_text.as_deref()),
        );
        let json = serde_json::to_string(&m).unwrap();
        assert!(
            json.contains(&serde_json::to_string(&mark).unwrap().replace('"', "")),
            "{json}"
        );
        let proto = m.encode_to_vec();
        let pipe = crate::screen::Screen::pipe();
        let text = crate::overview::status(&m, &pipe, false);
        let whole = crate::overview::status(&m, &pipe, true);
        for (form, bytes) in [
            ("json", json.as_bytes()),
            ("proto", &proto),
            ("text", text.as_bytes()),
            ("coverage", whole.as_bytes()),
        ] {
            assert!(
                !bytes.windows(token.len()).any(|w| w == token.as_bytes()),
                "{form}"
            );
        }

        // This Mac's page from the answer of `immunity machine`, whose reasons are given whole.
        let answers = super::Answers {
            machine: Box::new(|id, files_anywhere| {
                let home = std::path::Path::new("/");
                Ok(crate::machine::answer(&conn, Some(id), home, files_anywhere, now)?.ok())
            }),
            ..super::Answers::none()
        };
        let pages = super::pages(&conn, &m, &answers, "store.db", now).unwrap();
        let page = |name: &str| {
            pages
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, html)| html.clone())
                .unwrap_or_else(|| panic!("{name}"))
        };
        // The page shows the line as the run printed it, never cut again.
        assert!(
            page(&format!("{}/changes.html", super::DETAILS)).contains(&format!(
                "<p class=\"muted mono\">{}</p>",
                super::esc_said(&line)
            )),
            "{}",
            page(&format!("{}/changes.html", super::DETAILS))
        );
        let summary = page(super::SUMMARY);
        // The reading that failed is a fault: the band says what its source said as data, as
        // the terminal does, each name and reason quoted, cut once.
        let said = format!(
            "\"~/.zshrc\": \"a tool answered: fetch https://example.invalid/?t={mark} refused\""
        );
        let fault = summary
            .split("<p class=\"sub fault\">! Could not read: <span class=\"said\">")
            .nth(1)
            .map_or("", |f| &f[..f.find("</span>").unwrap()]);
        assert!(fault.contains(&super::esc_said(&said)), "{summary}");
        // What not covered says a source said, as the status gives it: cut once, where it was
        // put together.
        let value = download.and_then(|u| u.value_text.clone()).unwrap();
        assert!(
            pages
                .iter()
                .any(|(_, html)| html.contains(&super::esc_said(&value))),
            "{value}"
        );
        // A mark the core made is never written again as a source's, and what the collector
        // printed keeps its own backslash written as a source's.
        assert!(
            m.not_covered
                .iter()
                .any(|u| u.value_text.as_deref() == Some("the log said \\u{5c}n")),
            "{m:#?}"
        );
        // A reason `immunity machine` gives whole is cut on the page of this Mac.
        let this_mac = page(&format!(
            "{}/{}.html",
            super::DETAILS,
            crate::pages::THIS_MAC
        ));
        assert!(this_mac.contains(&mark), "{this_mac}");
        for (name, html) in &pages {
            assert!(!html.contains(&token), "{name}");
            assert!(!html.contains("\\u{5c}cut{gitleaks"), "{name}");
        }
    }
}
