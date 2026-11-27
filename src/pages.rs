//! The pages a person lands on: the summary, which answers what the app answers; what is
//! watched on this Mac, kind by kind; and what is beyond it. Every sentence is in plain
//! words: what something means for the owner, and whether he can do something about it.
//! The summary says a state and its faults at the top, as the default status decides them
//! (`overview::told`); what is read, in the table, a row drawn as a fault only by a fault of the
//! status; and every limit of this version here once, collapsed, at its end (`not_read_here.rs`).
//! Whether a thing not covered is a fault or a limit is the status's word (`Uncovered.fault`):
//! the pages decide neither. The other pages are reached from the links at the bottom of the
//! summary.
//!
//! Every link on the summary leads to a section that lists exactly what its label says,
//! under a heading that says it, first thing on arrival.
//!
//! The band, the footer, the table of findings (`findings_table.rs`) and the page of rules
//! (`rules.rs`) are drawn from the messages the commands answer (`view::Answers`), and print
//! names and text from a source through `secrets::Name` and `secrets::Said`. Text the rest reads
//! from the store goes through `esc`, as on every page of the view.

pub(crate) mod beyond;
pub(crate) mod findings_table;
pub(crate) mod rules;

use crate::contract::v1;
use crate::covered::{self, Count, Uncovered, YOU};
use crate::secrets::Name;
use crate::view::{self, DETAILS, FOOT, Latest, Out, counted, esc, esc_said, utc, utc_or};
use crate::{findings, integrity, servers, watched};
use rusqlite::{Connection, params};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write;

/// The person's pages of details, by file name in the folder of details.
pub const THIS_MAC: &str = "this-mac";
/// The heading of that page, which a link to it is named by.
pub const THIS_MAC_TITLE: &str = "What is watched on this Mac";
pub const BEYOND: &str = "beyond";
/// Every source of threat data, with the list of vulnerabilities used in attacks.
pub const THREAT_DATA: &str = "threats";
/// Every published rule this build ships.
pub const RULES: &str = "rules";
/// The heading of that page and of the summary's section about it.
const RULES_TITLE: &str = "Published rules";
/// The heading of that page, which the tile leading to it is named by.
pub(crate) const THREAT_DATA_TITLE: &str = "Threat data";
pub const TECHNICAL: &str = "technical";
pub const VULNERABILITIES: &str = "vulnerabilities";

/// The link back to the summary, on every page of details.
const BACK: &str = "<nav class=\"meta\"><a href=\"../view.html\">← What needs a look</a></nav>\n";

/// The anchor of a kind of watched thing: its words in lower case, joined by dashes.
pub fn anchor(what: &str) -> String {
    what.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}

/// Words as they begin a line: `Startup items`. A name written in lower case stays so.
pub fn capital(s: &str) -> String {
    if s.starts_with("npm ") {
        return s.to_string();
    }
    let mut chars = s.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// `1,234`.
fn grouped(n: i64) -> String {
    counted(n, "", "").trim_end().to_string()
}

/// What each kind of watched thing is, in a line.
fn about(what: &str) -> &'static str {
    match what {
        "startup items" => {
            "Programs macOS starts by itself when you log in or the Mac starts: the usual way for something unwanted to stay on a Mac."
        }
        covered::LOGIN_HOOKS => {
            "Scripts the login window runs with full control at every login and logout, a way Apple replaced years ago."
        }
        "shell startup files" => "Files your terminal runs every time it opens a shell.",
        "SSH files" => "Your SSH settings, and the keys allowed to log in to this Mac.",
        covered::LOGIN_MODULES => {
            "The rules and plugins that decide how you log in, unlock and approve an administrator action, and how your password is checked."
        }
        "git hooks in projects" => {
            "Scripts git runs by itself in your projects, for example before a commit."
        }
        "applications" => "Applications in the Applications folders, with who signed each.",
        "Homebrew packages" => "What Homebrew installed in /opt/homebrew or /usr/local.",
        "npm packages" => {
            "Packages npm installed for every project at once in /opt/homebrew/lib/node_modules or /usr/local/lib/node_modules."
        }
        "app code kept outside the app" => {
            "Code that applications not made by Apple keep in your Library folder, outside the application itself."
        }
        covered::DEPENDENCIES => {
            "Packages your projects list in their crates.io, npm and PyPI lockfiles, compared at every check with the known vulnerabilities and malicious packages of those ecosystems."
        }
        _ => crate::autorun::about(what),
    }
}

/// The summary page, a report read from the top: the state in the panel's words, with one line
/// on what it rests on; the findings as a table, open, answered and all, each row opening in
/// place to its evidence as `immunity finding` gives it; what is watched, area by area, with its
/// state and when it was last read; "As it happens", every program start checked against
/// published rules (`happens.rs`); the faults the person can fix; once, collapsed, what this
/// version does not read here (`not_read_here.rs`); and a line of links to the other pages.
/// Built from the state and the result
/// `immunity status --json` gives, so the two agree.
pub fn summary(
    conn: &Connection,
    st: &crate::status::State,
    r: &v1::Status,
    answers: &view::Answers,
    now: i64,
) -> Result<String, Box<dyn Error>> {
    let mut out = view::head("What needs a look").replacen("<body>", "<body class=\"summary\">", 1);
    let latest = view::latest_coverage(conn)?;
    let map = crate::map::read(conn, st, &latest)?;
    let (faults, limits) = sorted(st, r);
    let fixable = fixable(&faults);
    // The scope of the answer, said once as a link to where each thing is named.
    state(&mut out, r, now)?;
    findings_table::table(&mut out, answers, now)?;
    let failed = failed_here(&faults).len();
    watched_table(conn, &mut out, st, &map, &latest, &faults, failed, now)?;
    crate::happens::draw(&mut out, r, &answers.rules, &answers.findings, now)?;
    you_can_fix(&mut out, &fixable)?;
    crate::not_read_here::section(&mut out, &limits)?;
    links(&mut out, r, now)?;
    out.push_str(FOOT);
    Ok(out)
}

/// The state's glyph, one shape for each state, as the panel draws it, so colour is never the
/// only sign: a disc with an exclamation mark in `--now` when something needs the person now; a
/// disc with an eye in `--look` when there are things to look at and none is urgent; a disc with
/// a tick in `--calm` for nothing to look at; a ring with a tick in `--look` for nothing to look
/// at while a fault stands (`in_part`); a ring with a clock in `--quiet` for an answer that is old; a
/// dashed ring with a question mark in `--quiet` when it is not known. The glyph's class names its
/// state, and the band takes a thin tint of the same colour from it. The colours are the
/// stylesheet's, defined once.
const GLYPH_NOW: &str = "<svg class=\"glyph now\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"20\" style=\"fill:var(--now)\"/><path d=\"M20 10.5v11\" style=\"stroke:var(--on);stroke-width:3.2;stroke-linecap:round\"/><circle cx=\"20\" cy=\"28.5\" r=\"2\" style=\"fill:var(--on)\"/></svg>";
const GLYPH_LOOK: &str = "<svg class=\"glyph look\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"20\" style=\"fill:var(--look)\"/><path d=\"M9.5 20c2.8-4.6 6.3-6.9 10.5-6.9s7.7 2.3 10.5 6.9c-2.8 4.6-6.3 6.9-10.5 6.9S12.3 24.6 9.5 20z\" style=\"fill:none;stroke:var(--on);stroke-width:2.4;stroke-linejoin:round\"/><circle cx=\"20\" cy=\"20\" r=\"3.2\" style=\"fill:var(--on)\"/></svg>";
const GLYPH_CALM: &str = "<svg class=\"glyph calm\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"20\" style=\"fill:var(--calm)\"/><path d=\"M12.5 20.5l5 5 10-11\" style=\"fill:none;stroke:var(--on);stroke-width:3.2;stroke-linecap:round;stroke-linejoin:round\"/></svg>";
const GLYPH_PART: &str = "<svg class=\"glyph look\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"19.25\" style=\"fill:none;stroke:var(--look);stroke-width:1.5\"/><path d=\"M12.5 20.5l5 5 10-11\" style=\"fill:none;stroke:var(--look);stroke-width:3;stroke-linecap:round;stroke-linejoin:round\"/></svg>";
const GLYPH_STALE: &str = "<svg class=\"glyph\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"19.25\" style=\"fill:none;stroke:var(--quiet);stroke-width:1.5\"/><circle cx=\"20\" cy=\"20\" r=\"10\" style=\"fill:none;stroke:var(--quiet);stroke-width:2.4\"/><path d=\"M20 14v6.5l4 2.5\" style=\"fill:none;stroke:var(--quiet);stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round\"/></svg>";
const GLYPH_UNKNOWN: &str = "<svg class=\"glyph\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"19.25\" style=\"fill:none;stroke:var(--quiet);stroke-width:1.5;stroke-dasharray:4 3\"/><path d=\"M15.8 16a4.3 4.3 0 1 1 6.1 3.9c-1.3.6-1.9 1.5-1.9 2.9v.7\" style=\"fill:none;stroke:var(--quiet);stroke-width:2.6;stroke-linecap:round\"/><circle cx=\"20\" cy=\"28.2\" r=\"1.7\" style=\"fill:var(--quiet)\"/></svg>";

/// "1 needs you now · 2 to look at": the findings Immunity Core marked urgent, and the rest of its
/// total, in the panel's words (`Panel.headline`).
fn needs_you(urgent: u64, total: u64) -> String {
    let rest = total.saturating_sub(urgent);
    let mut parts = Vec::new();
    if urgent > 0 {
        parts.push(if urgent == 1 {
            "1 needs you now".to_string()
        } else {
            format!("{} need you now", grouped(urgent as i64))
        });
    }
    if rest > 0 {
        parts.push(format!("{} to look at", grouped(rest as i64)));
    }
    parts.join(" · ")
}

/// The state band: the glyph and the headline in the panel's words, then one short line: this
/// Mac's name as data, why the headline cannot say more when it cannot, the state the terminal
/// says under its headline, the last full check and when the page was made; under it every
/// fault the terminal lists (`band`). All of it is the status's: the findings counted as it
/// counts them, each of a pair one. A state the page cannot work out is said as not known,
/// never as calm.
fn state(out: &mut String, r: &v1::Status, now: i64) -> Out {
    let m = r.this_mac.clone().unwrap_or_default();
    let not_computed: Vec<&v1::NotComputed> = r
        .not_computed
        .iter()
        .filter(|n| n.section == "needs_a_look")
        .collect();
    let (total, urgent) = r
        .needs_a_look
        .as_ref()
        .map_or((0, 0), |n| (n.total, n.urgent_total));
    // Why the headline cannot say more, in the program's own words, set beside the name.
    let mut why: Vec<String> = not_computed.iter().map(|n| esc(&n.reason)).collect();
    // The glyph and the words by the status's own headline: calm only when it is calm.
    use v1::Headline as H;
    let (glyph, headline) = match H::try_from(r.headline) {
        // Red only for urgent ones; orange for things to look at, none urgent.
        Ok(H::NeedsALook) if urgent > 0 => (GLYPH_NOW, esc(&needs_you(urgent, total))),
        Ok(H::NeedsALook) => (GLYPH_LOOK, esc(&needs_you(urgent, total))),
        Ok(H::NotChecked) if m.state == v1::ThisMacState::NotChecked as i32 => {
            (GLYPH_UNKNOWN, "Nothing has been checked yet.".to_string())
        }
        // Why it is not fresh is the state under it, as the terminal says it.
        Ok(H::NotChecked | H::Stale) => (
            GLYPH_STALE,
            match m.checked_at {
                Some(t) => format!("Not checked since {}", view::when(t, now)),
                None => "No full check has finished".to_string(),
            },
        ),
        Ok(H::Calm) => (GLYPH_CALM, "Nothing needs you".to_string()),
        Ok(H::InPart) => (GLYPH_PART, "Nothing needs you".to_string()),
        _ => {
            if why.is_empty() {
                why.push(match r.needs_a_look {
                    None => "what needs a look is not known yet".to_string(),
                    Some(_) => "whether this Mac is watched is not known".to_string(),
                });
            }
            (GLYPH_UNKNOWN, "I can't tell".to_string())
        }
    };
    // Its name now, which can differ from the one in its id.
    let mut parts: Vec<String> = m.name_text.iter().map(|n| Name::given(n).html()).collect();
    parts.extend(why);
    let (said, faults) = band(r);
    parts.extend(said);
    parts.push(match m.checked_at {
        Some(t) => format!("last check {}", view::when(t, now)),
        None => "no full check yet".to_string(),
    });
    parts.push(format!("page made {}", view::when(now, now)));
    if r.running {
        parts.push("a check was running".to_string());
    }
    writeln!(
        out,
        "<section id=\"this-mac\">\n{glyph}\n<div>\n<h1>{headline}</h1>\n<p class=\"sub\">{}</p>\n{faults}</div>\n</section>",
        parts.join(" · ")
    )?;
    Ok(())
}

/// The terminal's times for the band's words: a page says them as `immunity status` does.
const TERMINAL: crate::screen::Screen = crate::screen::Screen {
    terminal: true,
    colour: false,
    width: None,
};

/// What the band says under its headline, as the default status decides it for the message
/// (`overview::told`), and nothing of its own: the state, for the line under the headline; and
/// each fault, a block of its own: `!` and the core's words, what the source said as data, the
/// words after it, its command after a middle dot, and what the person can do on a line under.
pub(crate) fn band(r: &v1::Status) -> (Option<String>, String) {
    let told = crate::overview::told(r, &TERMINAL);
    let run = |c: Option<&str>| {
        c.map_or(String::new(), |c| {
            format!(
                " · <span class=\"cmd\"><span class=\"mono\">{}</span>{COPY}</span>",
                esc(c)
            )
        })
    };
    let state = (told.state.as_ref()).map(|(words, c)| format!("{}{}", esc(words), run(*c)));
    let faults = (told.faults.iter())
        .map(|f| {
            let (words, said, tail, c, advice) = f.parts();
            let said = said.map_or(String::new(), |s| {
                format!(": <span class=\"said\">{}</span>", esc_said(s))
            });
            let advice = advice.map_or(String::new(), |a| {
                format!("<span class=\"advice\">{}</span>", esc(a))
            });
            format!(
                "<p class=\"sub fault\">! {}{said}{}{}{advice}</p>\n",
                esc(words),
                esc(tail),
                run(c)
            )
        })
        .collect();
    (state, faults)
}

/// The button beside the command an agent reads a finding with, fixed: the one script shows it
/// and copies the text of the command beside it (`src/happens.js`), so without the script there
/// is no button. Its icon is drawn by the style sheet, so a summary with many findings stays small.
pub(crate) const COPY: &str = "<button class=\"copy\" type=\"button\" aria-label=\"Copy the command\" title=\"Copy the command\" hidden></button>";

/// How a row of what is watched stands: its dot's classes and its words, which are safe HTML.
/// Read, in full or as far as this version reads here, is a filled dot of `--calm`; a fault a
/// hollow one of `--look`; none here or a plain count a filled one of `--quiet`; never checked a
/// hollow one of `--quiet`. Only coverage: findings are not repeated here.
struct Standing {
    dot: &'static str,
    said: String,
}

impl Standing {
    /// Read, in full or as far as this version reads here.
    fn read(said: &str) -> Standing {
        Standing {
            dot: " calm",
            said: esc(said),
        }
    }

    /// None here, or a count that is neither calm nor a gap.
    fn none(said: String) -> Standing {
        Standing { dot: "", said }
    }

    /// A fault.
    fn not(said: String) -> Standing {
        Standing {
            dot: " off look",
            said,
        }
    }

    /// Never checked.
    fn never(said: &str) -> Standing {
        Standing {
            dot: " off",
            said: esc(said),
        }
    }
}

/// One row of what is watched: the kind of place, how often it is looked at, how many things,
/// its state and when it was last read. The count leads, where `href` is given, to the things.
fn watched_row(
    out: &mut String,
    id: Option<&str>,
    (kind, how): (&str, &str),
    (things, href): (&str, Option<&str>),
    states: &[Standing],
    last: Option<i64>,
    now: i64,
) -> Out {
    let id = id.map_or(String::new(), |id| format!(" id=\"{id}\""));
    let said: Vec<String> = states
        .iter()
        .map(|s| format!("<span class=\"dot{}\"></span>{}", s.dot, s.said))
        .collect();
    writeln!(
        out,
        "<div class=\"wr\"{id}><span>{}</span><span class=\"wh2 t2\">{}</span><span class=\"wn\">{}</span><span class=\"wc\">{}</span><span class=\"wl\">{}</span></div>",
        esc(kind),
        esc(how),
        match href {
            Some(href) => format!(
                "<a href=\"{href}\" aria-label=\"{}: {}\">{}</a>",
                esc(kind),
                esc(things),
                esc(things)
            ),
            None => esc(things),
        },
        said.join(" · "),
        last.map_or("<span class=\"none\">—</span>".to_string(), |t| {
            view::when(t, now)
        })
    )?;
    Ok(())
}

/// Whether any record that affects a project is one attackers are using, counted from the same
/// tables the findings are raised from.
fn any_used(conn: &Connection) -> rusqlite::Result<bool> {
    Ok(crate::vulnerabilities::affecting(conn)?
        .iter()
        .any(|a| a.exploited))
}

/// The latest reading time among some readings.
fn last_read(readings: &[&Latest]) -> Option<i64> {
    readings.iter().map(|r| r.at).max()
}

/// What is watched, as a table by kind of place, grouped as on this Mac, in your projects and
/// beyond this Mac: how often each is looked at, how many things, its state and when it was last
/// read, from the latest readings in the store. A row's state is one of three: the faults of the
/// message that name it, linked to where they are told, and only they are drawn as faults; else
/// how it was read, "read in full" and "none here" only where every reading that fills the row is
/// full, "read" where something left it short, and "not checked yet" with no reading of it; else
/// a plain count. A limit is never a row's fault: it is told once, at the end. Then one line: how
/// many faults on this Mac nothing the person does changes, as a link to the page that names each.
#[allow(clippy::too_many_arguments)]
fn watched_table(
    conn: &Connection,
    out: &mut String,
    st: &crate::status::State,
    map: &crate::map::Map,
    latest: &[Latest],
    faults: &[&Uncovered],
    failed: usize,
    now: i64,
) -> Out {
    let m = &st.this_mac;
    let this = covered::this_machine(conn)?;
    let mac = findings::This::of(conn, this.clone())?;
    let place = |scope: &str| findings::place(scope, mac.as_ref());
    // What the faults name, each a place's name alone (`covered::Example`), so it is matched
    // whole; and those of them the person can fix.
    let named = |list: &[&Uncovered]| -> BTreeSet<String> {
        (list.iter())
            .flat_map(|u| u.examples.iter().map(|e| e.name.clone()))
            .collect()
    };
    let (at_fault, can_fix) = (named(faults), named(&fixable(faults)));
    // Where a fault is told in full: "You can fix", or the page of what could not be read, its
    // label naming that place before what the row says.
    let told = |fixable: bool, said: String| {
        let (href, at) = match fixable {
            true => ("#you-can-fix".to_string(), "You can fix"),
            false => (
                format!("{DETAILS}/{THIS_MAC}.html#{NOT_READ}"),
                NOT_READ_TITLE,
            ),
        };
        let said = esc(&said);
        Standing::not(format!(
            "<a href=\"{href}\" aria-label=\"{at}: {said}\">{said}</a>"
        ))
    };
    writeln!(
        out,
        "<section id=\"watched-here\">\n<div class=\"wsh\"><h2>What is watched</h2><span class=\"n\">on this Mac, in your projects and beyond</span></div>\n<div class=\"wt\">\n<div class=\"wr wh\" aria-hidden=\"true\"><span>Kind of place</span><span>How often</span><span class=\"wn\">Things</span><span>State</span><span class=\"wl\">Last read</span></div>"
    )?;
    let mut on_mac = String::new();
    let mut in_projects = String::new();
    for (count, what, fast) in covered::watched() {
        let how = if m.live && fast {
            "within seconds"
        } else {
            "at full checks"
        };
        let readings = readings_of(count, latest);
        let n = m.watched.iter().find(|w| w.0 == what).map(|w| w.1);
        // Its things a fault names: a reading of it that failed, the walk that finds the
        // projects it is kept in, or a watched file.
        let walks = (latest.iter()).filter(|r| {
            covered::in_projects(count)
                && (crate::project::FOUND_BY.iter())
                    .any(|(by, kind)| r.reader == *by && r.kind == *kind)
        });
        let mut cannot: BTreeSet<String> = (readings.iter().copied().chain(walks))
            .filter(|r| covered::failed(r))
            .map(|r| place(&r.scope))
            .filter(|p| at_fault.contains(p))
            .collect();
        if let Count::Files(as_) = count {
            let files: Vec<String> = conn
                .prepare(
                    "SELECT DISTINCT subject FROM assertion
                     WHERE layer = 'live' AND reader = ?1 AND predicate = 'watched_as'
                       AND object = ?2 ORDER BY subject",
                )?
                .query_map(params![watched::READER, as_], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            cannot.extend((files.iter().map(|f| place(f))).filter(|p| at_fault.contains(p)));
        }
        // Read in full only where every reading of it is full and not dated ahead of the clock,
        // the walk that finds its projects was whole, and for the packages the vulnerability
        // data is current. Whatever of that is short is a fault only by the message's word.
        let mut walk = walk_gap(count, latest, this.as_deref());
        if let Count::Dependencies = count {
            walk.extend(old_feeds(conn, now)?);
        }
        let whole = walk.is_empty()
            && (readings.iter())
                .all(|r| r.completeness == "full" && crate::store::age(r.at, now).is_some());
        let mut faulted: Vec<Standing> = Vec::new();
        if !cannot.is_empty() {
            let fixable = cannot.iter().all(|p| can_fix.contains(p));
            let said = format!("{} can't be read now", grouped(cannot.len() as i64));
            faulted.push(told(fixable, said));
        }
        // The faults of what the packages are compared with, by the message's items.
        let by = |ids: &[&str], said: &str| {
            let of: Vec<&&Uncovered> = (faults.iter())
                .filter(|u| ids.contains(&u.cause.id))
                .collect();
            (!of.is_empty()).then(|| told(of.iter().all(|u| u.cause.who == YOU), said.into()))
        };
        if let Count::Dependencies = count {
            let data = [
                covered::VULNERABILITY_DATA_OLD.id,
                covered::VULNERABILITY_DATA_FIXABLE.id,
            ];
            faulted.extend(by(&data, "vulnerability data not current"));
        }
        let mut things = n.map_or("—".to_string(), grouped);
        // The packages' own state, and beside it what the comparison found.
        let (mut read, mut beside) = (None, Vec::new());
        if let Count::Dependencies = count {
            if let Some(n) = n {
                things = grouped(n);
            }
            let t = crate::vulnerabilities::totals(conn, now)?;
            // At every check only where every project was compared in full; why one was not is
            // a fault above or a limit at the end.
            // And compared at all only where a project was: with none, nothing is said read.
            let all = whole && map.projects_open() == 0;
            read = Some(match (t.matched, t.projects_compared, all) {
                (false, ..) => Standing::never("not compared yet"),
                (true, 0, _) => Standing::never("no project compared"),
                (true, _, true) => Standing::read("compared at every check"),
                (true, _, false) => Standing::read("compared"),
            });
            if t.matched {
                let known: usize = t
                    .records_by_label
                    .iter()
                    .filter(|(label, _)| *label != "malicious")
                    .map(|(_, n)| n)
                    .sum();
                if known > 0 {
                    beside.push(Standing::none(format!(
                        "<a href=\"{DETAILS}/{VULNERABILITIES}.html\">{}</a>",
                        esc(&counted(
                            known as i64,
                            "known vulnerability",
                            "known vulnerabilities"
                        ))
                    )));
                    // "None used in attacks" rests on a current list of them
                    // (`vulnerabilities::exploited`); one that is used is a finding, in the
                    // table of findings. Its fault is the list's download, by the message's items.
                    if !any_used(conn)? {
                        let list = [covered::THREATS_UNREAD.id, covered::THREATS_FIXABLE.id];
                        let unknown = "whether any is used in attacks is not known";
                        let current = crate::vulnerabilities::catalogue_current(conn, now)?;
                        beside.push(match current {
                            false => {
                                by(&list, unknown).unwrap_or_else(|| Standing::none(esc(unknown)))
                            }
                            true => Standing::read("none is known to be used in attacks"),
                        });
                    }
                }
            }
        }
        let read = read.unwrap_or_else(|| {
            // With no reading of it, a count proves nothing read.
            if readings.is_empty() {
                return Standing::never("not checked yet");
            }
            // Of a kind kept in projects, while projects were not looked for everywhere:
            // what was read is the projects found.
            let found = covered::in_projects(count) && not_entered(latest, this.as_deref());
            match (n.unwrap_or(0) == 0, found, whole) {
                (true, true, true) => Standing::none("none in the projects found".to_string()),
                (true, false, true) => Standing::none("none here".to_string()),
                (_, true, _) => Standing::read("read in the projects found"),
                (false, false, true) => Standing::read("read in full"),
                (_, false, false) => Standing::read("read"),
            }
        });
        let mut states = match faulted.is_empty() {
            true => vec![read],
            false => faulted,
        };
        states.extend(beside);
        let id = matches!(count, Count::Dependencies).then_some("vulnerabilities");
        let href = format!("{DETAILS}/{THIS_MAC}.html#{}", anchor(what));
        let group = if covered::in_projects(count) || matches!(count, Count::Dependencies) {
            &mut in_projects
        } else {
            &mut on_mac
        };
        watched_row(
            group,
            id,
            (&capital(what), how),
            (&things, n.is_some().then_some(href.as_str())),
            &states,
            last_read(&readings),
            now,
        )?;
    }
    for (group, rows) in [("On this Mac", &on_mac), ("In your projects", &in_projects)] {
        if !rows.is_empty() {
            writeln!(out, "<p class=\"wg\">{group}</p>\n{rows}")?;
        }
    }
    // Servers, checked only when the person runs the server check. A person with no servers is
    // not told about servers at all. Its faults are the status's: servers that could not be
    // opened, and those the last server check did not finish on. Else "checked" rests on every
    // server's latest visit having read it in full, whatever findings rest on it.
    if !map.servers.is_empty() || map.on_servers > 0 {
        let mut states = Vec::new();
        for (cause, words) in [
            (&covered::SERVERS_NOT_OPENED, "could not be opened"),
            (&covered::SERVERS_NOT_CHECKED, "not checked last time"),
        ] {
            let n: usize = (faults.iter().filter(|u| u.cause.id == cause.id))
                .map(|u| u.count)
                .sum();
            if n > 0 {
                let said = format!("{} {words}", grouped(n as i64));
                states.push(told(cause.who == YOU, said));
            }
        }
        if states.is_empty() {
            states.push(match map.servers_checked {
                0 => Standing::never("not checked yet"),
                n if n == map.servers.len() => Standing::read("checked at the last server check"),
                n => Standing::none(esc(&format!(
                    "{} checked at the last server check",
                    grouped(n as i64)
                ))),
            });
        }
        let visits: Vec<&Latest> = latest
            .iter()
            .filter(|r| r.reader == servers::READER && r.kind == servers::VISIT)
            .collect();
        out.push_str("<p class=\"wg\">Beyond this Mac</p>\n");
        let listed = format!("{DETAILS}/{BEYOND}.html#servers");
        watched_row(
            out,
            None,
            (
                "Servers you log in to over SSH",
                "when you run the server check",
            ),
            (&grouped(map.servers.len() as i64), Some(listed.as_str())),
            &states,
            last_read(&visits),
            now,
        )?;
    }
    out.push_str("</div>\n");
    if failed > 0 {
        writeln!(
            out,
            "<p class=\"nj\" id=\"limits\"><a href=\"{DETAILS}/{THIS_MAC}.html#{NOT_READ}\">{} on this Mac could not be read</a></p>",
            counted(failed as i64, "thing", "things")
        )?;
    }
    out.push_str("</section>\n");
    Ok(())
}

/// The anchor of what could not be read on this Mac, on the page of what is watched.
pub const NOT_READ: &str = "not-read";
/// Its heading.
const NOT_READ_TITLE: &str = "Could not be read on this Mac";

/// Every thing not covered, as the faults and the limits, each in the order of the status: whether
/// one is a fault is the message's word (`Uncovered.fault`), item for item, since the message is
/// made from the same list (`status::uncovered_message`). One the message does not hold as the
/// same cause is a fault, so nothing is quieted by a message that differs.
fn sorted<'a>(
    st: &'a crate::status::State,
    r: &v1::Status,
) -> (Vec<&'a Uncovered>, Vec<&'a Uncovered>) {
    let fault = |i: usize, u: &Uncovered| {
        (r.not_covered.get(i))
            .filter(|m| m.id == u.cause.id)
            .is_none_or(|m| m.fault)
    };
    let (faults, limits): (Vec<_>, Vec<_>) = st
        .not_covered
        .iter()
        .enumerate()
        .partition(|(i, u)| fault(*i, u));
    let items = |list: Vec<(usize, &'a Uncovered)>| list.into_iter().map(|(_, u)| u).collect();
    (items(faults), items(limits))
}

/// The faults the person can do something about, told under "You can fix".
fn fixable<'a>(faults: &[&'a Uncovered]) -> Vec<&'a Uncovered> {
    faults
        .iter()
        .copied()
        .filter(|u| u.cause.who == YOU)
        .collect()
}

/// The faults nothing the person does changes, such as a reading or a download that failed, told
/// under "Could not be read on this Mac". With `fixable`, every fault, each once.
fn failed_here<'a>(faults: &[&'a Uncovered]) -> Vec<&'a Uncovered> {
    faults
        .iter()
        .copied()
        .filter(|u| u.cause.who != YOU)
        .collect()
}

/// The faults the person can fix, one cause beside another: what it is, every example as data,
/// and Immunity Core's advice. A limit with advice is told among the limits.
fn you_can_fix(out: &mut String, fixable: &[&Uncovered]) -> Out {
    writeln!(
        out,
        "<section id=\"you-can-fix\">\n<div class=\"wsh\"><h2>You can fix</h2><span class=\"n\">{}</span></div>",
        esc(&counted(fixable.len() as i64, "thing", "things"))
    )?;
    if fixable.is_empty() {
        out.push_str("<p class=\"empty\">Nothing for you to fix.</p>\n");
    } else {
        out.push_str("<div class=\"fixg\">\n");
        for u in fixable {
            writeln!(
                out,
                "<article class=\"fixc\" id=\"{}\">\n<p class=\"fct\">{}</p>",
                esc(u.cause.id),
                esc(&u.title())
            )?;
            let apart = apart(u);
            if !apart.is_empty() {
                out.push_str("<ul>\n");
                for item in &apart {
                    writeln!(out, "<li>{item}</li>")?;
                }
                out.push_str("</ul>\n");
            }
            writeln!(
                out,
                "<p class=\"fad\">{}</p>\n<p class=\"fad\">{}</p>\n</article>",
                esc(&u.meaning()),
                esc(u.cause.advice)
            )?;
        }
        out.push_str("</div>\n");
    }
    out.push_str("</section>\n");
    Ok(())
}

/// The links to the other pages, and when the page was made and on which Mac.
fn links(out: &mut String, r: &v1::Status, now: i64) -> Out {
    let name = r.this_mac.as_ref().and_then(|m| m.name_text.as_deref());
    writeln!(
        out,
        "<footer class=\"links\">\n<a href=\"{DETAILS}/{RULES}.html\">{RULES_TITLE}</a>\n<a href=\"{DETAILS}/{TECHNICAL}.html\">Technical details</a>\n</footer>\n<p class=\"wfoot\">Page made at {} by immunity view{}</p>",
        view::when(now, now),
        name.map_or(String::new(), |n| format!(
            " on <span class=\"mono\">{}</span>",
            Name::given(n).html()
        ))
    )?;
    Ok(())
}

/// A kind of thing that is listed as watched and that no rule speaks about.
const KEPT_AS_LIST: &str = "Kept as a list. Nothing tells you about a change here in this version.";
/// The mark of a rule whose findings notify at once.
const NOTIFIES: &str = "Sends a notification";
/// The rule about a match of a list of indicators, which is about no one kind.
const INDICATOR_RULE: &str = "indicator.match";
/// The rule about places read for the first time, which is about every watched kind.
const FIRST_READ_RULE: &str = "watched.first-read";

/// What the owner is told about: each rule's title and what it means, marked where its
/// findings notify at once; for no rule, that the thing is only kept as a list. The page of
/// what is watched says it under each kind.
fn told(out: &mut String, rules: &[findings::Rule]) -> Out {
    if rules.is_empty() {
        writeln!(out, "<p class=\"muted\">{}</p>", esc(KEPT_AS_LIST))?;
        return Ok(());
    }
    out.push_str("<ul class=\"rules\">\n");
    for r in rules {
        let mark = if findings::urgent(r.severity, Some(r.confidence)) {
            format!(" <span class=\"badge notify\">{NOTIFIES}</span>")
        } else {
            String::new()
        };
        writeln!(
            out,
            "<li>{}{mark}<br><span class=\"muted\">{}</span></li>",
            esc(r.words.title),
            esc(r.words.meaning)
        )?;
    }
    out.push_str("</ul>\n");
    Ok(())
}

/// The rules with one id, as `told` takes them.
fn rule_with(id: &str) -> Vec<findings::Rule> {
    findings::rules()
        .into_iter()
        .filter(|r| r.id == id)
        .collect()
}

/// Whether a list of indicators was read at the last full check: `Some(true)` read in full,
/// `Some(false)` given and not read, `None` not given.
fn indicator_list(conn: &Connection) -> rusqlite::Result<Option<bool>> {
    let Some(run) = crate::status::latest_finished(conn)? else {
        return Ok(None);
    };
    conn.query_row(
        "SELECT MAX(completeness = 'full') FROM coverage
         WHERE run_id = ?1 AND reader = ?2 AND kind = ?3",
        params![
            run.id,
            crate::indicators::READER,
            crate::indicators::LIST_KIND
        ],
        |r| r.get::<_, Option<bool>>(0),
    )
}

/// On the page of what is watched, after the kinds: the rules about no one kind, so that every
/// rule the owner can be told by is named on that page.
fn also(conn: &Connection, out: &mut String) -> Result<(), Box<dyn Error>> {
    out.push_str("<section id=\"also\">\n<h2>Also told</h2>\n<h3>A list of signs of a known attack, when you give one</h3>\n");
    told(out, &rule_with(INDICATOR_RULE))?;
    let said = match indicator_list(conn)? {
        Some(true) => "A list was read at the last check.",
        Some(false) => "A list was given but could not be read at the last check.",
        None => "No list has been given, so nothing is compared.",
    };
    writeln!(
        out,
        "<p class=\"muted\">{said}</p>\n<h3>Every watched place</h3>"
    )?;
    told(out, &rule_with(FIRST_READ_RULE))?;
    out.push_str("</section>\n");
    Ok(())
}

/// What the summary says first of known vulnerabilities.
const VULNERABILITIES_SAY: &str = "These are published weaknesses in packages your projects depend on. They are listed, not alarmed: most matter only under particular conditions. A package known to be malicious, or a vulnerability attackers are using, is shown at the top as something that needs a look.";
/// A label as a person reads it.
fn label_words(label: &str) -> &'static str {
    match label {
        "malicious" => "Malicious package",
        "critical" => "Critical",
        "high" => "High",
        "moderate" => "Moderate",
        "low" => "Low",
        _ => "No label",
    }
}

/// One known vulnerability as a row: package and release, project, label, fixed release,
/// record with its source. Text from the record is escaped by `td`.
fn vulnerability_row(
    out: &mut String,
    a: &crate::vulnerabilities::Affecting,
    project: bool,
    this: Option<&findings::This>,
) -> Out {
    let releases: Vec<String> = a.affected().into_iter().map(|(v, _)| v).collect();
    out.push_str("<tr>");
    view::td(
        out,
        "mono",
        &format!("{} {}", a.package, releases.join(", ")),
    )?;
    if project {
        view::td(out, "mono", &findings::place(&a.checkout, this))?;
    }
    view::td(out, "", label_words(a.label))?;
    view::td(out, "mono", &a.fixed.join(", "))?;
    view::td(
        out,
        "mono",
        &format!(
            "{} ({})",
            a.advisory,
            crate::vulnerabilities::source_name(&a.advisory)
        ),
    )?;
    out.push_str("</tr>\n");
    Ok(())
}

/// Every known vulnerability in packages the projects use, grouped by project.
pub fn vulnerabilities(conn: &Connection, now: i64) -> Result<String, Box<dyn Error>> {
    let mut out = top(
        "Known vulnerabilities in packages your projects use",
        &format!("This page made {}", utc(now)),
    );
    writeln!(
        out,
        "<section id=\"by-project\">\n<h2>Known vulnerabilities by project</h2>\n<p class=\"muted\">{}</p>\n<p class=\"muted\">{}</p>",
        esc(VULNERABILITIES_SAY),
        esc(crate::vulnerabilities::DECLARED)
    )?;
    let this = findings::This::of(conn, covered::this_machine(conn)?)?;
    let list = crate::vulnerabilities::affecting(conn)?;
    let gap = vulnerability_gap(conn, now)?;
    // Of the projects found, while not all were. Which folders this version does not enter is
    // a limit of the version, which the commands say; a search that failed is said here.
    let (found, scope) = covered::Found::of(Some(&crate::vulnerabilities::projects_found(conn)?));
    let scope = scope.filter(|_| found == covered::Found::LookedAt);
    let none = match found {
        covered::Found::All => "None is known.".to_string(),
        f => format!("None is known in {}.", f.projects()),
    };
    // "None" only when every project was compared; else the status's own sentence, by count.
    let matched = crate::text::Matched::of_totals(&crate::vulnerabilities::totals(conn, now)?);
    let all = matched.all_compared();
    coverage_of_list(&mut out, gap.as_deref(), all && list.is_empty(), &none);
    if !all {
        writeln!(
            out,
            "<p class=\"muted\">{}.</p>",
            esc(&capital(&matched.said(
                found,
                u64::try_from(crate::store::checkouts(conn)?).ok()
            )))
        )?;
    }
    if let Some(line) = scope {
        writeln!(out, "<p class=\"muted\">{}</p>", esc(&line))?;
    }
    let mut projects: BTreeMap<&str, Vec<&crate::vulnerabilities::Affecting>> = BTreeMap::new();
    for a in &list {
        projects.entry(a.checkout.as_str()).or_default().push(a);
    }
    for (checkout, of) in projects {
        writeln!(
            out,
            "<h3 class=\"mono\">{}</h3>\n<div class=\"scroll\"><table class=\"dense\">",
            esc(&findings::place(checkout, this.as_ref()))
        )?;
        view::thead(&mut out, &["Package", "Label", "Fixed in", "Record"]);
        for a in of {
            vulnerability_row(&mut out, a, false, this.as_ref())?;
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");
    out.push_str(FOOT);
    Ok(out)
}

/// One example of a thing not covered, as safe HTML: its name, and beside it what its source said
/// of it. What a source said is prose from it: cut, as every such text is where it is printed,
/// and escaped apart from the name.
fn example(name: &str, reason: Option<&str>) -> String {
    match reason {
        Some(r) => format!("{}: {}", esc(name), esc_said(&view::said(r))),
        None => esc(name),
    }
}

/// What is told apart from a thing's words, as safe HTML: every example with what its source
/// said, then the value, what sources said of it, such as why a download failed, cut where it
/// was put together (`covered::Uncovered::value`).
pub(crate) fn apart(u: &Uncovered) -> Vec<String> {
    let mut out: Vec<String> = u
        .examples
        .iter()
        .map(|e| example(&e.name, e.reason.as_deref()))
        .collect();
    out.extend(u.value.as_deref().map(esc_said));
    out
}

/// At most this many examples are listed under one thing not covered.
pub(crate) const EXAMPLES_SHOWN: usize = 20;

/// One thing not covered, in full: its title, where, what it means and what to do.
fn uncovered(out: &mut String, u: &Uncovered) -> Out {
    writeln!(
        out,
        "<article class=\"item\" id=\"{}\">\n<h3>{}</h3>",
        esc(u.cause.id),
        esc(&u.title())
    )?;
    let apart = apart(u);
    if !apart.is_empty() {
        out.push_str("<ul class=\"readings mono\">\n");
        for item in apart.iter().take(EXAMPLES_SHOWN) {
            writeln!(out, "<li>{item}</li>")?;
        }
        if apart.len() > EXAMPLES_SHOWN {
            writeln!(
                out,
                "<li class=\"muted\">and {} more</li>",
                apart.len() - EXAMPLES_SHOWN
            )?;
        }
        out.push_str("</ul>\n");
    }
    writeln!(
        out,
        "<p>{}</p>\n<p class=\"advice\">{}</p>\n</article>",
        esc(&u.meaning()),
        esc(u.cause.advice)
    )?;
    Ok(())
}

/// The projects on this Mac, as they are shown, with how many dependencies are known of each.
fn projects(conn: &Connection, this: Option<&str>) -> rusqlite::Result<Vec<(String, i64)>> {
    let Some(this) = this else {
        return Ok(Vec::new());
    };
    let mac = findings::This::of(conn, Some(this.to_string()))?;
    // The dependencies are counted in one pass over them, not once per project: no index
    // leads from a project to what is part of it.
    let list: Vec<(String, i64)> = conn
        .prepare(
            "SELECT a.subject, COALESCE(p.n, 0)
             FROM assertion a
             LEFT JOIN (SELECT object, COUNT(DISTINCT subject) AS n FROM assertion
                        WHERE layer = 'live' AND predicate = 'part_of' GROUP BY object) p
               ON p.object = a.subject
             WHERE a.layer = 'live' AND a.predicate = 'located_on' AND a.object = ?1
               AND a.subject LIKE 'checkout:%'
             GROUP BY a.subject ORDER BY a.subject",
        )?
        .query_map([this], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(list
        .into_iter()
        .map(|(id, n)| (findings::place(&id, mac.as_ref()), n))
        .collect())
}

/// Every source of threat data the summary's tile counts, from the same result the tile is
/// built from: first the scale, the short list of vulnerabilities used in attacks beside every
/// record of known vulnerabilities held; then the list, then each set of records, one section
/// each, saying what it is, how much it holds, when it was read and whether that is current,
/// and what it is compared with here. A source never read or not current says so, and nothing
/// says it was compared.
pub fn threat_data(conn: &Connection, r: &v1::Status, now: i64) -> Result<String, Box<dyn Error>> {
    let mut out = top(THREAT_DATA_TITLE, &format!("This page made {}", utc(now)));
    let fresh = r
        .vulnerabilities
        .as_ref()
        .map(|v| v.feeds.clone())
        .unwrap_or_default();
    let held = |source: &str| -> v1::FeedState {
        r.vulnerability_data
            .as_ref()
            .and_then(|d| d.feeds.iter().find(|f| f.source == source).cloned())
            .unwrap_or_default()
    };
    let entries = r.threats.as_ref().and_then(|t| t.entries);
    // The scale: only counts the program has, and none where a source was never read.
    let read: Vec<(&str, i64)> = fresh
        .iter()
        .filter(|f| f.read_at.is_some())
        .map(|f| {
            let records = held(&f.source).records.unwrap_or_default();
            (f.ecosystem.as_str(), records as i64)
        })
        .collect();
    // A count, big, and what it counts beside it.
    let figure = |n: i64, one: &str, many: &str| {
        format!(
            "<p><span class=\"num\">{}</span> <span>{}</span></p>\n",
            grouped(n),
            esc(if n == 1 { one } else { many })
        )
    };
    out.push_str("<div class=\"scale\">\n");
    match entries {
        Some(n) => out.push_str(&figure(
            n as i64,
            "vulnerability known to be used in real attacks",
            "vulnerabilities known to be used in real attacks",
        )),
        None => out.push_str("<p class=\"quiet\">The list of vulnerabilities used in real attacks has not been read.</p>\n"),
    }
    if read.is_empty() {
        out.push_str("<p class=\"quiet\">No record of known vulnerabilities has been read.</p>\n");
    } else {
        let names: Vec<&str> = read.iter().map(|(e, _)| *e).collect();
        let of = format!(
            "of known vulnerabilities and malicious packages, for {} packages",
            covered::listed(&names)
        );
        out.push_str(&figure(
            read.iter().map(|(_, n)| n).sum(),
            &format!("record {of}"),
            &format!("records {of}"),
        ));
    }
    out.push_str("</div>\n");
    // The two side by side are explained only where both are counts.
    if entries.is_some() && !read.is_empty() {
        out.push_str("<p class=\"muted\">The first is the short list of what attackers are known to use. The second is every record the program holds from OSV, the open database of published vulnerabilities, for the packages named; most of them are never used in an attack.</p>\n");
    }

    crate::view::catalogue(conn, &mut out, now)?;

    let compared = crate::vulnerabilities::catalogue_compared(conn)?;
    for f in &fresh {
        let source = f.source.as_str();
        let eco = f.ecosystem.as_str();
        let h = held(source);
        let asked = crate::osv::FEEDS
            .iter()
            .find(|feed| feed.source == source)
            .map_or("", |feed| feed.asked);
        writeln!(
            out,
            "<section id=\"{}\">\n<h2>Known vulnerabilities in {} packages</h2>\n<p>Records from OSV, the open database of published vulnerabilities, for {} packages, including packages known to be malicious. It is read {}.</p>",
            anchor(source),
            esc(eco),
            esc(eco),
            esc(asked)
        )?;
        let at = f.read_at;
        // Counts exist only for a feed read whole.
        if let (Some(at), Some(records)) = (at, h.records) {
            writeln!(
                out,
                "<p class=\"facts\"><strong>{}</strong> {}, {} among them · last read {}{}</p>",
                grouped(records as i64),
                if records == 1 { "record" } else { "records" },
                counted(
                    h.malicious_records.unwrap_or_default() as i64,
                    "malicious package",
                    "malicious packages"
                ),
                esc(&utc(at)),
                if f.current { " · current" } else { "" }
            )?;
        }
        let said = match (at, f.current) {
            (None, _) => format!(
                "<p class=\"quiet\">Never read, so none of your {} packages is compared with it.</p>",
                esc(eco)
            ),
            (Some(_), false) => format!(
                "<p class=\"quiet\">Not current: {}. Until it is read again, a {} package it says nothing about is not known to be clear.</p>",
                esc(f.not_current_why.as_deref().unwrap_or("no reason given")),
                esc(eco)
            ),
            (Some(_), true) if compared.contains(&eco) => format!(
                "<p>Compared at the last check with the {} packages in your projects' lockfiles.</p>",
                esc(eco)
            ),
            (Some(_), true) => format!(
                "<p class=\"quiet\">No {} packages from your projects' lockfiles were compared with it at the last check.</p>",
                esc(eco)
            ),
        };
        writeln!(out, "{said}\n</section>")?;
    }
    out.push_str(FOOT);
    Ok(out)
}

/// At most this many readings are named under a list that is not whole.
const GAPS_SHOWN: usize = 3;
/// What an empty list says when everything that fills it was read in full and fresh.
const NONE_FOUND: &str = "None found here.";

/// What a list cannot claim, from the latest readings that fill it: `None` when there is at
/// least one and every one is full and fresh, that is taken by the latest check and dated no
/// later than now (`store::age`); else a sentence naming each one that is not, with why and
/// when it was last read in full, and `extra`, what else the list rests on that is not current.
/// A list states that nothing is there only when this is `None` (`absent`).
fn unread(
    readings: &[&Latest],
    latest_run: Option<i64>,
    now: i64,
    extra: &[String],
) -> Option<String> {
    let fresh = |r: &Latest| crate::look::fresh(r.at, latest_run, now);
    let mut seen = BTreeSet::new();
    let mut said: Vec<String> = readings
        .iter()
        .filter(|r| r.completeness != "full" || !fresh(r))
        .map(|r| {
            let why = match (r.completeness.as_str(), r.reason.as_deref()) {
                ("full", _) => "not read at the latest check".to_string(),
                // What the reader's source said: cut, as every such text where it is printed.
                (_, Some(reason)) => view::said(reason),
                (_, None) => "not read in full".to_string(),
            };
            let last = r.last_full.map_or("never read in full".to_string(), |at| {
                format!("last read in full {}", utc(at))
            });
            format!("{} ({why}; {last})", r.kind)
        })
        .filter(|s| seen.insert(s.clone()))
        .collect();
    if said.len() > GAPS_SHOWN {
        let more = said.len() - GAPS_SHOWN;
        said.truncate(GAPS_SHOWN);
        said.push(format!("and {more} more"));
    }
    said.extend(extra.iter().cloned());
    if readings.is_empty() && extra.is_empty() {
        return Some("Not read yet, so what is here is not known.".to_string());
    }
    (!said.is_empty()).then(|| {
        format!(
            "Not read in full, so this list may not be whole: {}.",
            said.join("; ")
        )
    })
}

/// What a list of a kind of watched thing rests on beside its own readings: for a kind kept in
/// projects, the walk that finds them (`covered::projects_gap`), so that no "none" is said of
/// projects the walk did not find.
fn walk_gap(count: Count, latest: &[Latest], this: Option<&str>) -> Vec<String> {
    covered::in_projects(count)
        .then(|| failed_walk(latest, this))
        .flatten()
        .into_iter()
        .collect()
}

/// Whether projects were looked for everywhere but in the folders this version does not enter:
/// what a page then says of projects is said of the projects found.
fn not_entered(latest: &[Latest], this: Option<&str>) -> bool {
    let found = covered::projects_found(latest, this);
    !found.all && v1::Cause::try_from(found.cause) == Ok(v1::Cause::NotGiven)
}

/// Why the projects a page lists may not be whole: a reading that failed. A folder this
/// version does not enter is a limit of the version, which the commands say; a page shows
/// what was read.
fn failed_walk(latest: &[Latest], this: Option<&str>) -> Option<String> {
    let found = covered::projects_found(latest, this);
    (!found.all && !not_entered(latest, this))
        .then_some(found.why)
        .flatten()
}

/// Why the counts of ways in projects may be short, as a page tells it: the reading of which
/// ways each project holds failed, or the search for projects did (`covered::ways_gap`, less
/// the folders this version does not enter).
fn ways_failed(latest: &[Latest], this: Option<&str>) -> Option<String> {
    if not_entered(latest, this) {
        return None;
    }
    covered::ways_gap(latest, this)
}

/// What an empty list of a kind kept in projects says while projects were not looked for
/// everywhere.
const NONE_IN_FOUND: &str = "None in the projects found.";

/// The readings that fill the list of a kind of watched thing on this Mac: of files, every
/// kind of place watched as it; of installed things, that kind; of the packages projects
/// depend on, finding the projects and reading their lockfiles.
fn readings_of(count: Count, coverage: &[Latest]) -> Vec<&Latest> {
    let kinds: Vec<String> = match count {
        Count::Files(as_) => covered::kinds_of(as_),
        Count::Installed(kind) => vec![kind.to_string()],
        Count::Dependencies => vec![
            crate::checkouts::KIND.to_string(),
            crate::agent_folders::KIND.to_string(),
        ],
    };
    coverage
        .iter()
        .filter(|r| {
            kinds.contains(&r.kind)
                || (matches!(count, Count::Dependencies) && r.reader == crate::lockfiles::READER)
        })
        .collect()
}

/// What a list of known vulnerabilities rests on and did not have at `now`: the projects'
/// lockfiles read, and the vulnerability data current.
fn vulnerability_gap(conn: &Connection, now: i64) -> rusqlite::Result<Option<String>> {
    let latest = view::latest_coverage(conn)?;
    let lockfiles: Vec<&Latest> = latest
        .iter()
        .filter(|r| r.reader == crate::lockfiles::READER)
        .collect();
    let old = old_feeds(conn, now)?;
    let latest_run = crate::status::latest_finished(conn)?.map(|r| r.started_at);
    Ok(unread(&lockfiles, latest_run, now, &old))
}

/// Each matched feed of vulnerability data that is not current, with why, as `unread` names a
/// gap.
fn old_feeds(conn: &Connection, now: i64) -> rusqlite::Result<Vec<String>> {
    Ok(crate::vulnerabilities::matched_freshness(conn, now)?
        .into_iter()
        .filter_map(|f| {
            f.not_current
                .map(|why| format!("the {} vulnerability data ({why})", f.feed.ecosystem))
        })
        .collect())
}

/// Writes what a list rests on when it is not whole, and, for an empty list, that nothing is
/// there only when it is (`unread`).
fn coverage_of_list(out: &mut String, unread: Option<&str>, empty: bool, absent: &str) {
    match unread {
        // What `unread` says, which holds what sources said, cut.
        Some(said) => {
            out.push_str("<p class=\"muted\">");
            out.push_str(&esc_said(said));
            out.push_str("</p>\n");
        }
        None if empty => {
            out.push_str("<p class=\"muted\">");
            out.push_str(&esc(absent));
            out.push_str("</p>\n");
        }
        None => {}
    }
}

/// The top of a page of details for a person.
fn top(title: &str, meta: &str) -> String {
    let mut out = view::head(title);
    out.push_str(BACK);
    out.push_str(&format!(
        "<header>\n<h1>{}</h1>\n<p class=\"meta\">{}</p>\n</header>\n",
        esc(title),
        esc(meta)
    ));
    out
}

/// What is watched on this Mac, one section per kind with the things of that kind, the projects,
/// and in full each fault nothing the person does changes, by the message (`sorted`).
pub fn this_mac(
    conn: &Connection,
    st: &crate::status::State,
    r: &v1::Status,
    now: i64,
) -> Result<String, Box<dyn Error>> {
    let mut out = top(
        THIS_MAC_TITLE,
        &format!(
            "Last full check {} · this page made {}",
            utc_or(st.this_mac.checked_at, "never"),
            utc(now)
        ),
    );
    let this = covered::this_machine(conn)?;
    let this = this.as_deref();
    let latest_run = crate::status::latest_finished(conn)?.map(|r| r.started_at);
    let of_kinds = |kinds: &[&str]| -> Vec<&Latest> {
        st.coverage
            .iter()
            .filter(|r| kinds.contains(&r.kind.as_str()))
            .collect()
    };
    for (count, what, _) in covered::watched() {
        writeln!(
            out,
            "<section id=\"{}\">\n<h2>{}</h2>\n<p class=\"muted\">{}</p>",
            anchor(what),
            esc(&capital(what)),
            esc(about(what))
        )?;
        told(&mut out, &covered::rules_about(what))?;
        match count {
            Count::Files(as_) => {
                let walk = walk_gap(count, &st.coverage, this);
                let gap = unread(&readings_of(count, &st.coverage), latest_run, now, &walk);
                let found = covered::in_projects(count) && not_entered(&st.coverage, this);
                let none = if found { NONE_IN_FOUND } else { NONE_FOUND };
                files(conn, &mut out, as_, this, gap.as_deref(), none)?
            }
            Count::Installed(kind) => {
                let gap = unread(&readings_of(count, &st.coverage), latest_run, now, &[]);
                installed(conn, &mut out, kind, this, gap.as_deref())?
            }
            Count::Dependencies => {
                let n: i64 = conn.query_row(
                    "SELECT COUNT(DISTINCT subject) FROM assertion
                     WHERE layer = 'live' AND reader = ?1 AND predicate = 'part_of'
                       AND scope LIKE ?2",
                    params![
                        crate::lockfiles::READER,
                        format!("checkout:{}/%", this.unwrap_or_default())
                    ],
                    |r| r.get(0),
                )?;
                writeln!(
                    out,
                    "<p>{} on this Mac depend on {} packages, each counted once per project; each project and its count are under Projects found below. <a href=\"{VULNERABILITIES}.html\">Known vulnerabilities in them</a> are listed by project.</p>",
                    if not_entered(&st.coverage, this) {
                        "The projects found"
                    } else {
                        "Your projects"
                    },
                    grouped(n)
                )?;
                // The count is of the projects found: a walk that failed is said under it.
                let walk = walk_gap(count, &st.coverage, this);
                let gap = unread(&readings_of(count, &st.coverage), latest_run, now, &walk);
                coverage_of_list(&mut out, gap.as_deref(), false, "");
            }
        }
        out.push_str("</section>\n");
    }
    // Running programs: what the latest sample saw, in numbers. No list is kept.
    writeln!(
        out,
        "<section id=\"{}\">\n<h2>{}</h2>\n<p class=\"muted\">While a watcher runs, it looks at the programs running under your user and where they connect, every {} seconds. Only a program or connection that needs a look is kept; no list of them is.</p>",
        anchor(covered::SAMPLED),
        esc(&capital(covered::SAMPLED)),
        crate::watch::SAMPLE.as_secs()
    )?;
    told(&mut out, &covered::rules_about(covered::SAMPLED))?;
    match crate::processes::last_sample(conn)? {
        Some((at, programs, connections)) => writeln!(
            out,
            "<p>The latest sample, taken {}, saw {} and {}.</p>",
            utc(at),
            counted(programs, "running program", "running programs"),
            counted(connections, "connection", "connections")
        )?,
        None => out.push_str("<p class=\"muted\">No sample has been taken yet.</p>\n"),
    }
    out.push_str("</section>\n");
    also(conn, &mut out)?;

    let gap = ways_failed(&st.coverage, this);
    ways(conn, &mut out, this, gap.as_deref())?;

    writeln!(
        out,
        "<section id=\"projects\">\n<h2>Projects found</h2>\n<p class=\"muted\">Folders of code kept with git that were found on this Mac, with how many of their dependencies are known from the files that list them. {}</p>",
        esc(&crate::checkouts::walked())
    )?;
    let list = projects(conn, this)?;
    let gap = unread(
        &of_kinds(&[crate::checkouts::KIND, crate::agent_folders::KIND]),
        latest_run,
        now,
        &[],
    );
    coverage_of_list(
        &mut out,
        gap.as_deref(),
        list.is_empty(),
        "None found in the folders looked into.",
    );
    if !list.is_empty() {
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(&mut out, &["Project", "Dependencies known"]);
        for (shown, n) in list {
            out.push_str("<tr>");
            view::td(&mut out, "mono", &shown)?;
            view::td(&mut out, "", &grouped(n))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");
    // What could not be read on this Mac, each thing in full, where the summary's line leads.
    let failed = failed_here(&sorted(st, r).0);
    if !failed.is_empty() {
        writeln!(
            out,
            "<section id=\"{NOT_READ}\">\n<h2>{NOT_READ_TITLE}</h2>\n<p class=\"muted\">{} could not be read at the last check. Each is tried again at every check.</p>",
            capital(&counted(failed.len() as i64, "thing", "things"))
        )?;
        for u in failed {
            uncovered(&mut out, u)?;
        }
        out.push_str("</section>\n");
    }
    out.push_str(FOOT);
    Ok(out)
}

/// What the section of the ways a project runs code by itself says first.
const WAYS: &str = "Files in a project that make a tool run code by itself during routine work, such as opening the folder or installing its packages. Each one listed is read, and a change in what it says is told, whether it is in your projects now or not.";

/// What the section of the places in the home folder says first.
const HOME_WAYS: &str = "Files and folders in your home folder where a developer tool keeps its own settings for what it runs by itself, such as the programs a coding agent starts or an editor's extensions. Each one listed is read, and a change in what it says is told, whether it is on this Mac now or not.";

/// The ways a project runs code by itself that this version reads, from the table in
/// `autorun`: the file, what runs it, whether the tool asks first, when it is read, and in how
/// many of the projects found it is; then, in a section of their own, the places of the home
/// folder, and whether this Mac holds each. A way this version does not read is not on the
/// page: the documents and the commands' machine form name it. While the reading of projects
/// failed (`gap`, from `ways_failed`), a way no project is known to hold is not counted as none.
fn ways(conn: &Connection, out: &mut String, this: Option<&str>, gap: Option<&str>) -> Out {
    use crate::autorun::{self, Part, Scope};
    // Which subjects hold a way: checkouts of this Mac by the start of their id, or this Mac
    // itself for the home folder.
    let holding = |name: &str, home: bool| -> rusqlite::Result<i64> {
        let this = this.unwrap_or_default();
        conn.query_row(
            "SELECT COUNT(DISTINCT subject) FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate = ?2 AND object = ?3
               AND CASE WHEN ?5 THEN subject = ?4
                        ELSE substr(subject, 1, length(?4)) = ?4 END",
            params![
                watched::READER,
                autorun::HOLDS,
                name,
                if home {
                    this.to_string()
                } else {
                    format!("checkout:{this}/")
                },
                home
            ],
            |r| r.get(0),
        )
    };
    for home in [false, true] {
        let (id, heading, intro, column) = if home {
            (
                "home-code-runs",
                "Places where a developer tool's own settings can make code run by itself",
                HOME_WAYS,
                "On this Mac",
            )
        } else {
            (
                "ways-code-runs",
                "Ways a project can make code run by itself",
                WAYS,
                "Projects found with it",
            )
        };
        writeln!(
            out,
            "<section id=\"{id}\">\n<h2>{}</h2>\n<p class=\"muted\">{}</p>",
            esc(heading),
            esc(intro)
        )?;
        let gap = gap.filter(|_| !home);
        if let Some(why) = gap {
            let said =
                format!("Not every project was looked at, so these counts may be short: {why}.");
            coverage_of_list(out, Some(&said), false, "");
        }
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(out, &["File", "What runs it", "Asks first", "Read", column]);
        let read = |p: &autorun::Point| p.part != Part::Present;
        for (p, way) in autorun::ways().filter(|(p, _)| (p.scope == Scope::Home) == home && read(p))
        {
            let words = if home {
                way.trigger.words_home()
            } else {
                way.trigger.words()
            };
            let runs = format!("{} ({})", capital(words), way.tool);
            let read = match p.part {
                Part::Entries => "Read: every entry",
                _ if p.hourly().is_some() => "Read at full checks",
                Part::Folders(_) => "Read: every folder, by name",
                _ => "Read",
            };
            let here = match p.scope {
                Scope::NamedBy(_) => "—".to_string(),
                Scope::Checkout | Scope::System => match holding(&p.name(), false)? {
                    0 if gap.is_some() => "Not known".to_string(),
                    n => grouped(n),
                },
                Scope::Home if holding(&p.name(), true)? > 0 => "Yes".to_string(),
                Scope::Home => "No".to_string(),
            };
            out.push_str("<tr>");
            view::td(out, "mono", &p.name())?;
            view::td(out, "", &runs)?;
            view::td(out, "", way.asks.words())?;
            view::td(out, "", read)?;
            view::td(out, "", &here)?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n</section>\n");
    }
    Ok(())
}

/// The watched files of one kind: where each is, when it was first seen and when it last
/// changed. Only checksums are kept, never content. `gap` is what the list cannot claim
/// (`unread`). An entry watched only for presence says so instead of when it changed.
fn files(
    conn: &Connection,
    out: &mut String,
    as_: &str,
    this: Option<&str>,
    gap: Option<&str>,
    none: &str,
) -> Out {
    let mac = findings::This::of(conn, this.map(str::to_string))?;
    let first: Vec<(String, i64)> = conn
        .prepare(
            "SELECT subject, MIN(observed_at) FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate = 'watched_as' AND object = ?2
             GROUP BY subject ORDER BY subject",
        )?
        .query_map(params![watched::READER, as_], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    coverage_of_list(out, gap, first.is_empty(), none);
    if first.is_empty() {
        return Ok(());
    }
    let presence = watched::presence_only(conn)?;
    let now = watched::content_now(conn)?;
    let has_content: BTreeSet<String> = conn
        .prepare(
            "SELECT DISTINCT subject FROM assertion
             WHERE layer = 'live' AND reader = ?1 AND predicate = 'has_content'",
        )?
        .query_map([watched::READER], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    // A file whose content or link target was replaced, and when the current one was seen.
    let changed: BTreeMap<String, i64> = conn
        .prepare(
            "SELECT l.subject, MAX(l.observed_at) FROM assertion l
             WHERE l.layer = 'live' AND l.reader = ?1 AND l.predicate IN ('has_content', 'links_to')
               AND EXISTS (SELECT 1 FROM assertion o
                           WHERE o.layer = 'retracted' AND o.reader = ?1 AND o.subject = l.subject
                             AND o.predicate IN ('has_content', 'links_to'))
             GROUP BY l.subject",
        )?
        .query_map([watched::READER], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    view::thead(out, &["File", "First seen", "Last changed"]);
    for (id, at) in first {
        out.push_str("<tr>");
        view::td(out, "mono", &findings::place(&id, mac.as_ref()))?;
        view::td(out, "nowrap", &utc(at))?;
        // Never "unchanged" of what the latest check did not read in full.
        let (class, last) = if let Some(n) = now.get(&id).filter(|n| !n.read()) {
            ("", n.not_read())
        } else if presence.contains(&id) {
            ("", watched::PRESENCE_ONLY.to_string())
        } else if let Some(t) = changed.get(&id) {
            ("nowrap", utc(*t))
        } else if !has_content.contains(&id) {
            ("", watched::NEVER_READ.to_string())
        } else {
            ("nowrap", "not since first seen".to_string())
        };
        view::td_said(out, class, &last)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n");
    Ok(())
}

/// One installed thing as a person reads it.
#[derive(Default)]
struct Installed {
    name: String,
    signed_by: BTreeSet<String>,
    version: BTreeSet<String>,
    at: String,
}

/// The installed things of one kind, each with its subject, named as a person reads it and in
/// the order of their names.
fn installed_list(
    conn: &Connection,
    kind: &str,
    this: Option<&str>,
) -> rusqlite::Result<Vec<(String, Installed)>> {
    let mac = findings::This::of(conn, this.map(str::to_string))?;
    let mut things: BTreeMap<String, Installed> = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT subject, predicate, object FROM assertion
         WHERE layer = 'live' AND reader = ?1 AND kind = ?2",
    )?;
    let rows = stmt.query_map(params![integrity::READER, kind], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (subject, predicate, object) = row?;
        let t = things.entry(subject).or_default();
        match predicate.as_str() {
            "signed_by" => {
                t.signed_by.insert(object);
            }
            "has_version" => {
                t.version.insert(object);
            }
            "installed_at" => t.at = object,
            _ => {}
        }
    }
    let mut list: Vec<(String, Installed)> = things
        .into_iter()
        .map(|(subject, mut t)| {
            if t.at.is_empty() {
                t.at = findings::place(&subject, mac.as_ref());
            }
            let path = t.at.trim_end_matches('/');
            let last = path.rsplit('/').next().unwrap_or(path);
            t.name = if let Some(app) = last.strip_suffix(".app") {
                app.to_string()
            } else if subject.starts_with("component:") {
                view::component_name(&subject).1.to_string()
            } else if let Some((_, keg)) = path.split_once("/Cellar/") {
                // A Homebrew keg, `<name>/<version>`.
                let (name, version) = keg.split_once('/').unwrap_or((keg, ""));
                if t.version.is_empty() && !version.is_empty() {
                    t.version.insert(version.to_string());
                }
                name.to_string()
            } else {
                last.to_string()
            };
            (subject, t)
        })
        .collect();
    list.sort_by_key(|(_, t)| t.name.to_lowercase());
    Ok(list)
}

/// The installed things of one kind: name first, who signed it where that is known, version
/// and where it is. `gap` is what the list cannot claim (`unread`).
fn installed(
    conn: &Connection,
    out: &mut String,
    kind: &str,
    this: Option<&str>,
    gap: Option<&str>,
) -> Out {
    let list: Vec<Installed> = installed_list(conn, kind, this)?
        .into_iter()
        .map(|(_, t)| t)
        .collect();
    coverage_of_list(out, gap, list.is_empty(), NONE_FOUND);
    if list.is_empty() {
        return Ok(());
    }
    let signed = list.iter().any(|t| !t.signed_by.is_empty());
    let join = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
    out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
    if signed {
        view::thead(out, &["Name", "Signed by", "Version", "Where"]);
    } else {
        view::thead(out, &["Name", "Version", "Where"]);
    }
    for t in &list {
        out.push_str("<tr>");
        view::td(out, "", &t.name)?;
        if signed {
            view::td(out, "", &join(&t.signed_by))?;
        }
        view::td(out, "mono", &join(&t.version))?;
        view::td(out, "mono", &t.at)?;
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n");
    Ok(())
}

/// The technical pages, each in a line: everything the program keeps, as it keeps it.
pub fn technical() -> String {
    let mut out = top(
        "Technical details",
        "Everything the program keeps, as it keeps it: for your agent, or for a closer look.",
    );
    out.push_str("<section id=\"technical\">\n<ul class=\"counts\">\n");
    out.push_str(&format!(
        "<li><a href=\"{THIS_MAC}.html\">{THIS_MAC_TITLE}: every kind of place, its things and its rules</a></li>\n<li><a href=\"{VULNERABILITIES}.html\">Known vulnerabilities in the packages your projects use</a></li>\n"
    ));
    out.push_str(&format!(
        "<li><a href=\"{BEYOND}.html\">Beyond this Mac: servers with what was read on each, your other devices, other people's devices, and machines you set aside</a></li>\n"
    ));
    out.push_str(&format!(
        "<li><a href=\"{THREAT_DATA}.html\">{THREAT_DATA_TITLE}: every source of known vulnerabilities, and the list of those used in attacks</a></li>\n"
    ));
    for (name, title) in view::DETAIL_PAGES {
        out.push_str(&format!(
            "<li><a href=\"{name}.html\">{}</a></li>\n",
            esc(title)
        ));
    }
    out.push_str("</ul>\n</section>\n");
    out.push_str(FOOT);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The band's glyph is the status's headline: the calm disc only for `calm`, the ring for
    /// `in_part`, the clock for `stale`, and the question mark for a headline not known. How this
    /// Mac is watched is said by the message's watcher, and one not live is never said to be.
    #[test]
    fn a_page_draws_the_calm_disc_only_for_a_calm_headline() {
        let now = 1_000_001;
        let draw = |r: &v1::Status| {
            let mut out = String::new();
            state(&mut out, r, now).unwrap();
            out
        };
        // A status that is calm by the core's rule: fresh, nothing to look at, this Mac watched
        // whole by a live watcher.
        let calm = crate::headline::headed(v1::Status {
            this_mac: Some(v1::ThisMac {
                state: v1::ThisMacState::Watched as i32,
                live: true,
                checked_at: Some(now - 1),
                fresh: true,
                ..Default::default()
            }),
            watching: Some(v1::Watcher::default()),
            needs_a_look: Some(v1::NeedsALook::default()),
            ..Default::default()
        });
        assert_eq!(calm.headline, v1::Headline::Calm as i32);
        let drawn = draw(&calm);
        assert!(
            drawn.contains(GLYPH_CALM) && drawn.contains("Watching live"),
            "{drawn}"
        );
        // Every other headline, set by hand to pick the glyph, never draws the calm disc.
        let band = |headline: v1::Headline| {
            let mut r = calm.clone();
            r.headline = headline as i32;
            draw(&r)
        };
        for (headline, glyph) in [
            (v1::Headline::InPart, GLYPH_PART),
            (v1::Headline::Stale, GLYPH_STALE),
            (v1::Headline::Unknown, GLYPH_UNKNOWN),
            (v1::Headline::Unspecified, GLYPH_UNKNOWN),
        ] {
            let drawn = band(headline);
            assert!(
                drawn.contains(glyph) && !drawn.contains(GLYPH_CALM),
                "{headline:?}: {drawn}"
            );
        }
        // Not checked: a Mac never checked says so, and one checked before says since when, by
        // the message's state of this Mac.
        let before = band(v1::Headline::NotChecked);
        assert!(
            before.contains("Not checked since") && before.contains(GLYPH_STALE),
            "{before}"
        );
        let mut r = calm.clone();
        r.headline = v1::Headline::NotChecked as i32;
        r.this_mac.as_mut().unwrap().state = v1::ThisMacState::NotChecked as i32;
        let never = draw(&r);
        assert!(
            never.contains("Nothing has been checked yet.") && never.contains(GLYPH_UNKNOWN),
            "{never}"
        );
        // The watcher's case is the message's: one that is not live is never said to be.
        let mut stopped = calm.clone();
        stopped.headline = v1::Headline::InPart as i32;
        (stopped.this_mac.as_mut().unwrap().live, stopped.watching) = (false, None);
        let stopped = draw(&stopped);
        assert!(
            stopped.contains("No watcher runs") && !stopped.contains("live"),
            "{stopped}"
        );
        // A watcher's failure is a fault: said once, under the line, as the terminal says it, and
        // the line says nothing of how much is read or of the failure.
        for (what, words) in [
            (crate::watch::FULL_CHECK, "full check"),
            (crate::watch::EVENTS, "reading of program starts"),
        ] {
            let mut r = calm.clone();
            r.headline = v1::Headline::InPart as i32;
            r.watching = Some(v1::Watcher {
                failed: vec![v1::WatcherFailure {
                    what: what.to_string(),
                    at: now,
                    detail_text: "invented refusal".to_string(),
                }],
                ..Default::default()
            });
            let failed = draw(&r);
            let sub = failed.split("<p class=\"sub fault\">").next().unwrap();
            assert!(
                sub.contains("<p class=\"sub\">Watching live · "),
                "{failed}"
            );
            assert!(
                !sub.contains(" failed") && !sub.contains("in part"),
                "{failed}"
            );
            let line = format!("<p class=\"sub fault\">! The watcher&#39;s latest {words} failed");
            assert_eq!(failed.matches(&line).count(), 1, "{failed}");
        }
    }

    /// A fault as a page draws it: its text with a mark where what the source said (`§s`), its
    /// command (`§c`) and its advice (`§a`) stand, and those three apart.
    type Drawn = (String, Option<String>, Option<String>, Option<String>);

    /// Takes the first `open`…`close` out of `text`, leaving `mark`, and gives what was inside.
    fn take(text: &mut String, open: &str, close: &str, mark: &str) -> Option<String> {
        let i = text.find(open)? + open.len();
        let j = i + text[i..].find(close)?;
        let inner = text[i..j].to_string();
        text.replace_range(i - open.len()..j + close.len(), mark);
        Some(inner)
    }

    /// The band of a page in parts: the line under the headline, its command taken out, and each
    /// fault.
    fn band_drawn(page: &str) -> ((String, Option<String>), Vec<Drawn>) {
        let command = |t: &mut String| {
            let close = format!("</span>{COPY}</span>");
            take(
                t,
                " · <span class=\"cmd\"><span class=\"mono\">",
                &close,
                "§c",
            )
        };
        let mut sub = page.split("<p class=\"sub\">").nth(1).unwrap().to_string();
        sub.truncate(sub.find("</p>").unwrap());
        let sub_command = command(&mut sub);
        let faults = (page.split("<p class=\"sub fault\">").skip(1))
            .map(|b| {
                let mut b = b[..b.find("</p>").unwrap()].to_string();
                let said = take(&mut b, "<span class=\"said\">", "</span>", "§s");
                let c = command(&mut b);
                let advice = take(&mut b, "<span class=\"advice\">", "</span>", "§a");
                (b, said, c, advice)
            })
            .collect();
        ((sub, sub_command), faults)
    }

    /// The pages and the text agree, as values: for every case of the watcher, a check not fresh
    /// with and without findings, and a status of real size with faults and with only limits,
    /// the band holds the state the default status decides (`overview::told`) on the line under
    /// its headline, and every fault it lists, in order, each with its own words, what its source
    /// said, its command and its advice, and nothing else; the state is never also a fault, the
    /// ring is drawn only while a fault stands, and a watcher that is starting is never said to be
    /// off. After `immunity on`, a job in place with no watcher and none restarting is off and not
    /// by `immunity off`, and never calm.
    #[test]
    fn the_band_holds_the_state_faults_and_commands_the_status_decides_and_nothing_else() {
        use crate::watch::{Case, EVENTS, READ};
        let now = 1_800_000_000;
        let on = now - 60;
        let failed = |what: &str| v1::Watcher {
            failed: vec![v1::WatcherFailure {
                what: what.to_string(),
                at: now - 5,
                detail_text: "an invented <refusal>".to_string(),
            }],
            ..Default::default()
        };
        let calm = || v1::Status {
            answered_at: now,
            ..crate::headline::tests::calm()
        };
        let off = |job: Option<bool>, entries: (Option<i64>, Option<i64>, Option<bool>)| {
            let mut s = calm();
            (s.this_mac.as_mut().unwrap().live, s.watching) = (false, None);
            s.login_job_installed = job;
            (s.turned_on_at, s.turned_off_at, s.turned_on_latest) = entries;
            s
        };
        let after_on = (Some(on), None, Some(true));
        let after_off = (Some(on - 60), Some(on), Some(false));
        let mut live_failed = calm();
        live_failed.watching = Some(failed(EVENTS));
        let mut full_failed = calm();
        full_failed.watching = Some(failed(crate::watch::FULL_CHECK));
        let mut failing = off(None, (None, None, None));
        failing.watching = Some(failed(READ));
        let mut starting = off(None, (None, None, None));
        starting.watching = Some(v1::Watcher::default());
        let mut restarting = off(Some(false), after_on);
        restarting.watcher_restarting_since_at = Some(now - 5);
        let cases = [
            (Some(Case::Live), calm()),
            (Some(Case::LiveFailed), live_failed),
            (Some(Case::LiveFailed), full_failed),
            (Some(Case::Failing), failing),
            (Some(Case::Starting), starting),
            (Some(Case::Restarting), restarting),
            (
                Some(Case::OffNotByCommand {
                    on,
                    job: Some(true),
                }),
                off(Some(true), after_on),
            ),
            (
                Some(Case::OffNotByCommand {
                    on,
                    job: Some(false),
                }),
                off(Some(false), after_on),
            ),
            (
                Some(Case::OffNotByCommand { on, job: None }),
                off(None, after_on),
            ),
            (
                Some(Case::OffByCommand { off: on }),
                off(Some(false), after_off),
            ),
            (Some(Case::JobInPlace), off(Some(true), after_off)),
            (
                Some(Case::NotInstalled),
                off(Some(false), (None, None, None)),
            ),
            (Some(Case::NoWatcher), off(None, (None, None, None))),
        ];
        // Not fresh with no watcher: the terminal takes the watcher for the state; with a finding,
        // it says the answer is not fresh as a fault.
        let mut stale = off(None, (None, None, None));
        stale.headline = v1::Headline::Stale as i32;
        let t = stale.this_mac.as_mut().unwrap();
        (t.fresh, t.stale_reason) = (false, Some("an invented reason".to_string()));
        let mut stale_found = stale.clone();
        stale_found.headline = v1::Headline::NeedsALook as i32;
        stale_found.needs_a_look = Some(v1::NeedsALook {
            total: 1,
            ..Default::default()
        });
        // A status of real size, with its faults, and with only limits.
        let sample = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/contract/samples/status-real-size.json"
        ));
        let mut real: v1::Status = serde_json::from_str(sample).unwrap();
        (real.answered_at, real.headline) = (now, v1::Headline::InPart as i32);
        real.needs_a_look = Some(v1::NeedsALook::default());
        let mut limits = real.clone();
        for u in &mut limits.not_covered {
            u.fault = false;
        }
        // No download failed either: the text says a failed one by the feeds themselves.
        (limits.watching, limits.threats, limits.vulnerability_data) =
            (Some(v1::Watcher::default()), None, None);
        limits.headline = v1::Headline::Calm as i32;
        // Live as `this_mac` says, with no watcher on the store, is no watcher; a watcher on the
        // store, not live, beside a restart's time is starting, and no restart is said.
        let mut left = calm();
        left.watching = None;
        assert_eq!(crate::watch::case(&left), Case::NoWatcher);
        let mut both = calm();
        both.this_mac.as_mut().unwrap().live = false;
        both.watcher_restarting_since_at = Some(now - 5);
        both.store = Some(v1::StoreFile {
            exists: true,
            ..Default::default()
        });
        assert_eq!(crate::watch::case(&both), Case::Starting);
        let mut drawn_both = String::new();
        state(&mut drawn_both, &both, now).unwrap();
        assert!(!drawn_both.contains("restarting"), "{drawn_both}");
        // Faults with commands of their own: a check that died, then no watcher.
        let mut died = off(None, (None, None, None));
        died.last_run = Some(v1::CheckMark {
            started_at: now - 600,
            ..Default::default()
        });
        let others = [
            (None, died),
            (None, left),
            (None, both),
            (None, stale),
            (None, stale_found),
            (None, real),
            (None, limits),
        ];
        for (case, s) in cases.into_iter().chain(others) {
            if let Some(case) = case {
                assert_eq!(crate::watch::case(&s), case);
            }
            let mut page = String::new();
            state(&mut page, &s, now).unwrap();
            let ((sub, sub_command), faults) = band_drawn(&page);
            let told = crate::overview::told(&s, &TERMINAL);
            // The state, in the line under the headline, its command after it.
            match &told.state {
                Some((words, c)) => {
                    let mark = if c.is_some() { "§c" } else { "" };
                    assert!(sub.contains(&format!("{}{mark}", esc(words))), "{page}");
                    assert_eq!(sub_command, c.map(esc), "{page}");
                }
                None => assert_eq!(sub_command, None, "{page}"),
            }
            let wanted: Vec<Drawn> = (told.faults.iter())
                .map(|f| {
                    let (words, from, tail, c, advice) = f.parts();
                    let text = format!(
                        "! {}{}{}{}{}",
                        esc(words),
                        if from.is_some() { ": §s" } else { "" },
                        esc(tail),
                        if c.is_some() { "§c" } else { "" },
                        if advice.is_some() { "§a" } else { "" },
                    );
                    (text, from.map(esc_said), c.map(esc), advice.map(esc))
                })
                .collect();
            assert_eq!(faults, wanted, "{page}");
            // The state is said once: no fault is the state's words.
            if let Some((words, _)) = &told.state {
                assert!(faults.iter().all(|f| !f.0.contains(&esc(words))), "{page}");
            }
            // Of the status of real size: the ring only while a fault stands, by the headline
            // that says so.
            if !s.not_covered.is_empty() {
                let calm = s.headline == v1::Headline::Calm as i32;
                assert_eq!(page.contains(GLYPH_PART), !calm, "{page}");
                assert_eq!(faults.is_empty(), calm, "{page}");
            }
            if let Some(case) = case {
                let band = format!("{sub} {faults:?}");
                if case == Case::Starting {
                    assert!(!band.contains("off"), "{band}");
                }
                if let Case::OffNotByCommand { .. } = case {
                    assert!(band.contains("did not turn it off"), "{band}");
                    let headline = crate::headline::headline(&s).0;
                    assert_ne!(headline, v1::Headline::Calm, "{case:?}");
                }
            }
        }
    }

    #[test]
    fn a_list_of_watched_places_or_of_ways_read_at_a_time_ahead_of_the_clock_never_says_none_found()
    {
        // A time from the future proves nothing, whichever kind of autorun point the list is
        // of: a kind of watched place, or a way a project runs code.
        let (run, now) = (1_000_000, 1_000_100);
        let mcp = crate::autorun::POINTS
            .iter()
            .find(|p| p.paths == [".mcp.json"])
            .unwrap();
        for (count, kind) in [
            (
                Count::Files(watched::PROFILE),
                watched::PROFILE_KIND.to_string(),
            ),
            (Count::Files(crate::autorun::AGENT_START.0), mcp.kind()),
        ] {
            let at = |at| Latest {
                reader: watched::READER.to_string(),
                scope: "machine:mac".to_string(),
                kind: kind.clone(),
                completeness: "full".to_string(),
                reason: None,
                cause: None,
                at,
                last_full: Some(at),
                ..Default::default()
            };
            let ahead = [at(now + crate::store::AHEAD_ALLOWED + 1)];
            let said = unread(&readings_of(count, &ahead), Some(run), now, &[]);
            assert!(said.is_some_and(|s| s.contains(&kind)), "{kind}");
            let on_time = [at(run)];
            assert_eq!(
                unread(&readings_of(count, &on_time), Some(run), now, &[]),
                None
            );
        }
    }

    #[test]
    fn a_list_says_nothing_is_there_only_when_every_reading_that_fills_it_is_full_and_fresh() {
        // "None found" on a list whose reading failed, was partial, was taken by an earlier
        // check, is dated ahead of the clock, or never ran, is false calm.
        let (run, now) = (1_000_000, 1_000_100);
        let reading = |completeness: &str, at: i64| Latest {
            reader: "invented".to_string(),
            scope: "machine:mac".to_string(),
            kind: "invented things".to_string(),
            completeness: completeness.to_string(),
            reason: (completeness != "full").then(|| "an invented reason".to_string()),
            cause: None,
            at,
            last_full: Some(run - 86_400),
            ..Default::default()
        };
        let said = |readings: &[&Latest], extra: &[String]| {
            let mut out = String::new();
            coverage_of_list(
                &mut out,
                unread(readings, Some(run), now, extra).as_deref(),
                true,
                NONE_FOUND,
            );
            out
        };
        let full = reading("full", run);
        assert!(said(&[&full], &[]).contains(NONE_FOUND));
        for not in [
            reading("partial", run),
            reading("none", run),
            reading("full", run - 1),
            reading("full", now + crate::store::AHEAD_ALLOWED + 1),
        ] {
            let out = said(&[&full, &not], &[]);
            assert!(
                !out.contains(NONE_FOUND)
                    && out.contains("invented things")
                    && out.contains("last read in full"),
                "{out}"
            );
        }
        assert!(!said(&[], &[]).contains(NONE_FOUND));
        // Many gaps are told briefly: the first few and how many more, each kind once.
        let many: Vec<Latest> = (0..5)
            .map(|i| Latest {
                kind: format!("invented kind {i}"),
                ..reading("none", run)
            })
            .collect();
        let mut refs: Vec<&Latest> = many.iter().collect();
        refs.push(&many[0]);
        let out = said(&refs, &[]);
        assert!(
            out.contains("invented kind 2 (")
                && out.contains("; and 2 more.")
                && !out.contains("invented kind 3")
                && out.matches("invented kind 0").count() == 1,
            "{out}"
        );
        let old = ["the invented data (it is old)".to_string()];
        let out = said(&[&full], &old);
        assert!(!out.contains(NONE_FOUND) && out.contains(&old[0]), "{out}");
        // Without any finished check, nothing is fresh.
        let mut out = String::new();
        coverage_of_list(
            &mut out,
            unread(&[&full], None, now, &[]).as_deref(),
            true,
            NONE_FOUND,
        );
        assert!(!out.contains(NONE_FOUND), "{out}");
        // A list that is not empty is not told as empty either way.
        let mut out = String::new();
        coverage_of_list(&mut out, None, false, NONE_FOUND);
        assert!(out.is_empty());
    }

    #[test]
    fn a_way_read_is_in_every_place_derived_from_the_table_so_adding_a_row_changes_no_code() {
        // Adding a product is adding a row. Every place that tells or acts on what runs by
        // itself takes it from the table: a row read here that one of them missed would be
        // read and never told, or told and never watched live.
        use crate::autorun;
        let dir = crate::common::Scratch::at(
            std::env::temp_dir().join(format!("immunity-ways-{}", std::process::id())),
        );
        std::fs::create_dir_all(&dir).unwrap();
        let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let mut page = String::new();
        ways(&conn, &mut page, None, None).unwrap();
        let registered: Vec<String> = conn
            .prepare("SELECT name FROM coverage_kind")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
        for (p, way) in autorun::ways() {
            let cell = format!("<td class=\"mono\">{}</td>", esc(&p.name()));
            // The page lists the ways that are read, and no way that is only known.
            assert_eq!(
                page.contains(&cell),
                p.part != autorun::Part::Present,
                "{}",
                p.name()
            );
            if p.part == autorun::Part::Present {
                continue;
            }
            // A row read only at full checks says so in its reading column.
            let rest = &page[page.find(&cell).unwrap()..];
            let line = &rest[..rest.find("</tr>").unwrap()];
            assert_eq!(
                line.contains(">Read at full checks<"),
                p.hourly().is_some(),
                "{line}"
            );
            if !p.read_here() {
                continue;
            }
            let as_ = p.watched_as().unwrap_or_default();
            let (_, what, line) = p.watched().unwrap_or_default();
            assert!(!as_.is_empty() && !line.is_empty(), "{}", p.name());
            // A row not watched live says why; a path with a `*` cannot be watched live.
            for path in p.paths {
                let live = match p.scope {
                    autorun::Scope::Home => {
                        autorun::home_places().iter().any(|(h, _, _)| h == path)
                    }
                    _ => autorun::files().iter().any(|(f, _)| f == path),
                };
                assert_eq!(live, p.hourly().is_none(), "{path}");
                assert!(!live || !path.contains('*'), "{path}");
            }
            assert!(registered.contains(&p.kind()), "{}", p.kind());
            assert!(autorun::kinds_of(as_).contains(&p.kind()));
            assert!(
                covered::watched()
                    .iter()
                    .any(|w| matches!(w.0, Count::Files(a) if a == as_) && w.1 == what)
            );
            assert_eq!(about(what), line);
            let rules = covered::rules_about(what);
            assert_eq!(rules.len(), 1, "{}", p.name());
            assert_eq!(
                (rules[0].technique, rules[0].severity, rules[0].confidence),
                (way.technique, way.severity, way.confidence),
                "{}",
                p.name()
            );
        }
    }

    #[test]
    fn every_kind_of_watched_place_says_on_the_page_what_it_is_and_which_rule_tells_of_it() {
        // A kind listed with no line leaves the owner a name without a meaning, and one no
        // rule speaks about is watched without anyone being told of a change.
        for (_, (watched_as, _)) in crate::autorun::places() {
            let (_, what, _) = covered::watched()
                .into_iter()
                .find(|w| matches!(w.0, Count::Files(a) if a == watched_as))
                .unwrap_or_else(|| panic!("{}", watched_as));
            assert!(about(what).ends_with('.'), "{what}");
            assert_eq!(covered::rules_about(what).len(), 1, "{what}");
        }
    }

    #[test]
    fn every_ecosystem_that_is_matched_is_named_in_each_sentence_that_says_what_is_compared() {
        // These sentences are written by hand; a lockfile reader for a new ecosystem fails this
        // until each names it, so none says less is compared than is.
        let sentences = [
            about(covered::DEPENDENCIES),
            covered::NOT_COMPARED.meaning,
            (covered::LIMITS.iter())
                .find(|(_, c)| c.id == covered::NOT_COMPARED.id)
                .unwrap()
                .0,
        ];
        for feed in crate::vulnerabilities::matched_feeds() {
            for said in sentences {
                assert!(said.contains(feed.ecosystem), "{}: {said}", feed.ecosystem);
            }
        }
    }

    /// The page of what is watched for a store nothing was read into, with a home that does
    /// not exist; the folder it made goes, also when the test fails.
    fn this_mac_page() -> String {
        let dir = crate::common::Scratch::new("told");
        let conn = crate::store::open_or_make(&dir.0.join("store.db")).unwrap();
        let st = crate::status::state(&conn, &dir.0.join("no-home"), 1_791_000_000).unwrap();
        this_mac(&conn, &st, &v1::Status::default(), 1_791_000_000).unwrap()
    }

    /// Each section of a kind of watched thing on the page, by its anchor, up to its end.
    fn kinds(page: &str) -> Vec<&str> {
        covered::watched()
            .into_iter()
            .map(|(_, what, _)| what)
            .chain([covered::SAMPLED])
            .map(|what| {
                let at = page
                    .find(&format!("<section id=\"{}\">", anchor(what)))
                    .unwrap_or_else(|| panic!("{what}"));
                &page[at..at + page[at..].find("</section>").unwrap()]
            })
            .collect()
    }

    /// Each line of what is told, as the text of its `<li>`.
    fn rule_lines(html: &str) -> Vec<&str> {
        html.split("<ul class=\"rules\">")
            .skip(1)
            .flat_map(|list| list[..list.find("</ul>").unwrap()].split("<li>").skip(1))
            .collect()
    }

    #[test]
    fn every_rule_is_on_the_page_of_what_is_watched() {
        // The owner reads on the page what he is told about. A rule added later and not
        // placed under a kind or under "Also told" would tell him something the page never
        // says it does.
        let page = this_mac_page();
        for r in findings::rules() {
            assert!(page.contains(&esc(r.words.title)), "{}: {page}", r.id);
            assert!(page.contains(&esc(r.words.meaning)), "{}: {page}", r.id);
        }
    }

    #[test]
    fn the_page_never_calls_a_thing_watched_without_saying_what_is_told_about_it() {
        // False calm: a kind listed as watched that no rule can fire about must say so in
        // words, or "watched" promises a warning that never comes.
        let page = this_mac_page();
        for kind in kinds(&page) {
            let said = kind.contains("<ul class=\"rules\">\n<li>") || kind.contains(KEPT_AS_LIST);
            assert!(said, "{kind}");
        }
        let mut lone = String::new();
        told(&mut lone, &[]).unwrap();
        assert!(lone.contains(KEPT_AS_LIST), "{lone}");
    }

    #[test]
    fn a_rule_marked_as_sending_a_notification_is_exactly_an_urgent_one() {
        // The page tells the owner which changes notify at once; the app notifies for what
        // is urgent. The two must not disagree.
        let page = this_mac_page();
        let lines = rule_lines(&page);
        for r in findings::rules() {
            let line = lines
                .iter()
                .find(|l| l.starts_with(&esc(r.words.title)))
                .unwrap_or_else(|| panic!("{} is not on the page", r.id));
            assert_eq!(
                line.contains(NOTIFIES),
                findings::urgent(r.severity, Some(r.confidence)),
                "{}: {line}",
                r.id
            );
        }
    }

    /// The part of a page from the section with `id` to its end, or nothing.
    fn section_of<'a>(html: &'a str, id: &str) -> &'a str {
        let rest = html
            .find(&format!("<section id=\"{id}\">"))
            .map_or("", |i| &html[i..]);
        &rest[..rest.find("</section>").unwrap_or(rest.len())]
    }

    /// Nothing is hidden and nothing is told twice: every thing not covered, for every cause of
    /// the catalogue, is on the pages once, a fault in its own section and a limit in the
    /// collapsed section at the end, by the message's `fault` alone; a limit's names are there
    /// only, and stay text.
    #[test]
    fn every_thing_not_covered_is_on_the_pages_once_a_fault_in_its_section_a_limit_at_the_end() {
        let dir = crate::common::Scratch::new("pages-once");
        let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let now = 1_800_000_000;
        let mut st = crate::status::state(&conn, &dir, now).unwrap();
        st.not_covered = (covered::CAUSES.iter())
            .map(|c| Uncovered {
                examples: vec![covered::Example::named(format!("<b>{}</b>", c.id))],
                ..Uncovered::new(c, 1)
            })
            .collect();
        let mut r = v1::Status {
            answered_at: now,
            not_covered: (st.not_covered.iter())
                .map(crate::status::uncovered_message)
                .collect(),
            ..Default::default()
        };
        // Both sorts of every cause: the message's word, then its opposite.
        for flip in [false, true] {
            for u in &mut r.not_covered {
                u.fault = (u.class == v1::Cause::Failed as i32) != flip;
            }
            let pages =
                view::pages(&conn, &st, &r, &view::Answers::none(), "store.db", now).unwrap();
            let page = |name: &str| &pages.iter().find(|(n, _)| n == name).unwrap().1;
            let summary = page(view::SUMMARY);
            let limits = section_of(summary, crate::not_read_here::ANCHOR);
            let all = |what: &str| -> usize {
                pages
                    .iter()
                    .map(|(_, html)| html.matches(what).count())
                    .sum()
            };
            for u in &r.not_covered {
                let (id, name) = (
                    format!("id=\"{}\"", u.id),
                    format!("&lt;b&gt;{}&lt;/b&gt;", u.id),
                );
                assert_eq!(all(&id), 1, "{} flip {flip}", u.id);
                assert_eq!(all(&format!("<b>{}", u.id)), 0, "{}", u.id);
                let home = match (u.fault, u.who == YOU) {
                    (false, _) => limits,
                    (true, true) => section_of(summary, "you-can-fix"),
                    (true, false) => {
                        section_of(page(&format!("{DETAILS}/{THIS_MAC}.html")), NOT_READ)
                    }
                };
                assert!(
                    home.contains(&id) && home.contains(&name),
                    "{} flip {flip}",
                    u.id
                );
                if !u.fault {
                    assert_eq!(all(&name), 1, "{} flip {flip}", u.id);
                }
            }
            let n = r.not_covered.iter().filter(|u| !u.fault).count();
            assert!(
                limits.contains(&format!("<span class=\"n\">{n} things</span>")),
                "{limits}"
            );
        }
        // A message that does not hold an item as the same cause makes it a fault, never a limit.
        let (faults, limits) = sorted(&st, &v1::Status::default());
        assert_eq!((faults.len(), limits.len()), (covered::CAUSES.len(), 0));
    }

    /// A row of what is watched is drawn as a fault only where a fault of the message names it,
    /// linked to where it is told, and says "read in full" only over readings all full, with the
    /// time of its own reading: one short by a limit, or read only at a check before the latest,
    /// is never drawn as a failure; a row with no reading is "not checked yet" whatever it counts,
    /// and the programs startup items run are read by their own reading.
    #[test]
    fn a_row_shows_a_fault_only_by_a_fault_and_read_in_full_only_over_readings_all_full() {
        let dir = crate::common::Scratch::new("rows-by-faults");
        let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
        let now = 1_800_000_000;
        crate::store::journal_note(&conn, now - 60, "run-1", "run_started", "").unwrap();
        crate::store::journal_note(&conn, now - 30, "run-1", "run_finished", "").unwrap();
        let mut st = crate::status::state(&conn, &dir, now).unwrap();
        st.this_mac.watched = vec![
            ("Homebrew packages", 1_234_567, "hourly"),
            ("programs startup items run", 3, "at checks"),
        ];
        let scope = "machine:example-mac";
        let reading = |completeness: &str, cause: Option<crate::store::Cause>| Latest {
            reader: integrity::READER.to_string(),
            scope: scope.to_string(),
            kind: integrity::KEGS.to_string(),
            completeness: completeness.to_string(),
            reason: cause.map(|_| "an invented reason".to_string()),
            cause: cause.map(|c| c.literal().to_string()),
            at: now - 40,
            last_full: Some(now - 40),
            ..Default::default()
        };
        let failed = Uncovered {
            examples: vec![covered::Example::named(findings::place(scope, None))],
            ..Uncovered::new(&covered::READING_FAILED, 1)
        };
        // The state and the last read of a row.
        let row = |latest: &[Latest], faults: &[&Uncovered], what: &str| -> (String, String) {
            let (mut out, map) = (String::new(), crate::map::Map::default());
            watched_table(&conn, &mut out, &st, &map, latest, faults, 0, now).unwrap();
            let row = out.lines().find(|l| l.contains(what)).unwrap();
            let cell = &row[row.find("<span class=\"wc\">").unwrap() + 17..];
            let (state, last) = cell.split_once("</span><span class=\"wl\">").unwrap();
            (
                state.to_string(),
                last.trim_end_matches("</span></div>").to_string(),
            )
        };
        let state = |latest: &[Latest], faults: &[&Uncovered]| row(latest, faults, "Homebrew").0;
        let calm = "<span class=\"dot calm\"></span>";
        assert_eq!(
            state(&[reading("full", None)], &[]),
            format!("{calm}read in full")
        );
        let limit = [reading("partial", Some(crate::store::Cause::NotGiven))];
        assert_eq!(state(&limit, &[]), format!("{calm}read"));
        let broken = [reading("none", Some(crate::store::Cause::Failed))];
        assert_eq!(
            state(&broken, &[&failed]),
            format!(
                "<span class=\"dot off look\"></span><a href=\"{DETAILS}/{THIS_MAC}.html#{NOT_READ}\" aria-label=\"{NOT_READ_TITLE}: 1 can&#39;t be read now\">1 can&#39;t be read now</a>"
            )
        );
        // A failure the message does not call a fault is no row's fault either.
        assert_eq!(state(&broken, &[]), format!("{calm}read"));
        // Read in full at a check before the latest: no fault of the message, and its own time.
        let earlier = Latest {
            at: now - 7200,
            last_full: Some(now - 7200),
            ..reading("full", None)
        };
        assert_eq!(
            row(std::slice::from_ref(&earlier), &[], "Homebrew"),
            (format!("{calm}read in full"), view::when(now - 7200, now))
        );
        // A count with no reading of it.
        assert_eq!(
            row(&[], &[], "Homebrew"),
            (
                "<span class=\"dot off\"></span>not checked yet".to_string(),
                "<span class=\"none\">—</span>".to_string()
            )
        );
        // The packages, orange only by a fault of the data they are compared with.
        let packages = |faults: &[&Uncovered]| row(&[], faults, "Packages your projects").0;
        assert_eq!(
            packages(&[]),
            "<span class=\"dot off\"></span>not compared yet"
        );
        let old = Uncovered::new(&covered::VULNERABILITY_DATA_OLD, 1);
        assert!(
            packages(&[&old]).starts_with("<span class=\"dot off look\"></span><a href="),
            "{}",
            packages(&[&old])
        );
        // The programs startup items run, by the reading that reads them.
        let targets = Latest {
            reader: watched::READER.to_string(),
            kind: crate::targets::KIND.to_string(),
            ..reading("full", None)
        };
        assert_eq!(
            row(&[targets], &[], "Programs startup items run"),
            (format!("{calm}read in full"), view::when(now - 40, now))
        );
    }
}
