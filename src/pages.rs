//! The pages a person lands on: the summary, which answers what the app answers; what is
//! watched on this Mac, kind by kind; and what is beyond it. Every sentence is in plain
//! words: what something means for the owner, and whether he can do something about it.
//! The summary says a state at the top, and counts what could not be read, as the default status
//! decides them (`overview::told`); what is read, in the table, a row drawn as a fault only by a
//! fault of the status; each thing that could not be read in full, once, in its own section; and
//! every limit of this version here once, collapsed, at its end (`not_read_here.rs`).
//! Whether a thing not covered is a fault or a limit is the status's word (`Uncovered.fault`):
//! the pages decide neither. The other pages are reached from the links at the bottom of the
//! summary.
//!
//! Every link on the summary leads to a section that lists exactly what its label says,
//! under a heading that says it, first thing on arrival.
//!
//! Every page is drawn from the messages the commands answer (`view::Answers` and the status),
//! and prints names and text from a source through `secrets::Name` and `secrets::Said` alone;
//! `esc` is for the core's own words, as on every page of the view.

pub(crate) mod beyond;
pub(crate) mod coverage;
pub(crate) mod findings_table;
mod not_read;
pub(crate) mod rules;
pub(crate) mod this_mac;
pub(crate) mod vulnerabilities;

use crate::contract::v1;
use crate::covered::{self, Count, Latest};
use crate::overview::Of;
use crate::secrets::{Name, Said};
use crate::view::{self, DETAILS, FOOT, Out, counted, esc};
use std::collections::BTreeSet;
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
/// What was read and how completely, from the coverage summary of the status.
pub const COVERAGE: &str = "coverage";
/// The heading of that page, which the link to it is named by.
const COVERAGE_TITLE: &str = "What was read and how completely";

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

/// Names from `_text` fields, each in its own element, joined by commas.
fn names(all: &[String]) -> String {
    let shown: Vec<String> = all.iter().map(|n| Name::given(n).html()).collect();
    shown.join(", ")
}

/// A reason a message gives whole, cut where it is shown.
fn said(whole: &str) -> String {
    Said::of(&crate::contract::unescape(whole)).html()
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

/// The summary page, a report read from the top: the state in the panel's words, with one line
/// on what it rests on; the findings as a table, open, answered and all, each row opening in
/// place to its evidence as `immunity finding` gives it; what is read, area by area, with its
/// state and when it was last read; "As it happens", every program start checked against
/// published rules (`happens.rs`); each thing that could not be read, in full (`not_read`); once,
/// collapsed, what this version does not read here (`not_read_here.rs`); and a line of links to
/// the other pages.
/// Drawn from what the commands answer alone, the status first, so the two agree.
pub fn summary(
    r: &v1::Status,
    answers: &view::Answers,
    now: i64,
) -> Result<String, Box<dyn Error>> {
    let mut out = view::head("What needs a look").replacen("<body>", "<body class=\"summary\">", 1);
    // Whether a thing not covered is a fault or a limit is the status's word.
    let limits: Vec<&v1::Uncovered> = r.not_covered.iter().filter(|u| !u.fault).collect();
    state(&mut out, r, now)?;
    findings_table::table(&mut out, answers, now)?;
    watched_table(&mut out, r, now)?;
    crate::happens::draw(&mut out, r, &answers.rules, &answers.findings, now)?;
    not_read::section(&mut out, r)?;
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
/// says under its headline, the last full check and when the page was made; under it each fault
/// of Immunity Core's own work, and, while something could not be read, one line that counts it
/// and leads to where each is told (`band`). All of it is the status's: the findings counted as
/// it counts them, each of a pair one. A state the page cannot work out is said as not known,
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
    let Band {
        state,
        faults,
        unread,
    } = band(r);
    parts.extend(state);
    parts.push(match m.checked_at {
        Some(t) => format!("last check {}", view::when(t, now)),
        None => "no full check yet".to_string(),
    });
    parts.push(format!("page made {}", view::when(now, now)));
    if r.running {
        parts.push("a check was running".to_string());
    }
    let lines: String = (faults.into_iter().chain(unread))
        .map(|line| format!("{line}\n"))
        .collect();
    writeln!(
        out,
        "<section id=\"this-mac\">\n{glyph}\n<div>\n<h1>{headline}</h1>\n<p class=\"sub\">{}</p>\n{lines}</div>\n</section>",
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

/// What the band says under its headline: the state, for the line under it; each fault of
/// Immunity Core's own work, a line of its own; and the line that counts what could not be read,
/// while something could not.
pub(crate) struct Band {
    pub(crate) state: Option<String>,
    pub(crate) faults: Vec<String>,
    pub(crate) unread: Option<String>,
}

/// What the band says under its headline, as the default status decides it for the message
/// (`overview::told`), and nothing of its own. The state is on the line under the headline. Each
/// fault the text lists is placed by what it is about (`overview::Of`), one rule for every one:
/// - a fault of Immunity Core's own work (a check that did not finish, a watcher that is off or
///   a failure of it that stands, an answer that is not fresh) stays in the band as it was, a
///   line of its own, `!` and the text's words, what its source said and its command;
/// - a reading that failed (a cause the status calls a fault, the event level and what it lost,
///   a download) is counted on one line, `!` and a link to "Could not be read", which tells each
///   whole (`not_read::line`): as many as the things it is about, a cause of a hundred servers a
///   hundred, with how many of them the person can fix.
///
/// So the band says less than the text of nothing and reads no calmer than a line for each: every
/// state and fault of its own work in its words, every reading that failed in the count, each
/// under the mark and in the ink a fault had.
pub(crate) fn band(r: &v1::Status) -> Band {
    let told = crate::overview::told(r, &TERMINAL);
    let state = (told.state.as_ref()).map(|(w, c)| fault_html(w, None, "", *c));
    // Only a cause carries advice (`overview::cause_fault`), and a cause is never a state.
    let faults = (told.faults.iter())
        .filter(|f| f.about() == Of::State)
        .map(|f| {
            let (words, said, tail, c, _) = f.parts();
            let said = said.map(|s| (s, f.said_is_ours()));
            format!(
                "<p class=\"sub fault\">! {}</p>",
                fault_html(words, said, tail, c)
            )
        })
        .collect();
    let unread = not_read::line(r, &format!("#{NOT_READ}"))
        .map(|line| format!("<p class=\"sub fault\">{line}</p>"));
    Band {
        state,
        faults,
        unread,
    }
}

/// A line of the default status on a page, as safe HTML: the core's words, what the source said
/// as data (or the core's own words in its place, `ours`), the words after it, and its command
/// after a middle dot.
fn fault_html(
    words: &str,
    said: Option<(&str, bool)>,
    tail: &str,
    command: Option<&str>,
) -> String {
    // What a source said, through the printer; the core's own words in its place as words.
    let said = said.map_or(String::new(), |(s, ours)| {
        let s = match ours {
            true => esc(s),
            false => crate::secrets::quoted_html(s),
        };
        format!(": <span class=\"said\">{s}</span>")
    });
    let command = command.map_or(String::new(), |c| {
        format!(
            " · <span class=\"cmd\"><span class=\"mono\">{}</span>{COPY}</span>",
            esc(c)
        )
    });
    format!("{}{said}{}{command}", esc(words), esc(tail))
}

/// The button beside the command an agent reads a finding with, fixed: the one script shows it
/// and copies the text of the command beside it (`src/happens.js`), so without the script there
/// is no button. Its icon is drawn by the style sheet, so a summary with many findings stays small.
pub(crate) const COPY: &str = "<button class=\"copy\" type=\"button\" aria-label=\"Copy the command\" title=\"Copy the command\" hidden></button>";

/// How a row of what is watched stands: its dot's classes and its words, which are safe HTML.
/// Read, in full or as far as this version reads here, is a filled dot of `--calm`; a fault a
/// hollow one of `--look`; none here or a plain count a filled one of `--quiet`; never checked a
/// hollow one of `--quiet`. Only coverage: findings are not repeated here.
#[derive(Debug, PartialEq)]
struct Standing {
    dot: &'static str,
    said: String,
}

/// What a row says when the status says its kind was read in full and fresh and nothing is there.
const NONE_HERE: &str = "none here";

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

/// The groups of what is read, in their order.
const ON_THIS_MAC: &str = "On this Mac";
const IN_PROJECTS: &str = "In your projects";
const BEYOND_THIS_MAC: &str = "Beyond this Mac";

/// Where the links of a table of what is read lead from the page it is on: the summary, with its
/// section "Could not be read", and the folder of the pages of details.
struct Links {
    summary: String,
    details: String,
}

impl Links {
    /// From the summary.
    fn summary() -> Links {
        Links {
            summary: String::new(),
            details: format!("{DETAILS}/"),
        }
    }

    /// From a page of details.
    fn details() -> Links {
        Links {
            summary: format!("../{}", view::SUMMARY),
            details: String::new(),
        }
    }
}

/// One row of what is read: its group, the kind of place in words, how often it is looked at, how
/// many things and where the count leads, its states and when it was last read.
struct Row {
    group: &'static str,
    id: Option<&'static str>,
    kind: String,
    how: &'static str,
    things: String,
    href: Option<String>,
    states: Vec<Standing>,
    last: Option<i64>,
}

impl Row {
    /// That all the row says is that there is none here, read in full and fresh: a row that says
    /// anything else, a fault, a reading short of full, no reading, is never folded.
    fn none_here(&self) -> bool {
        self.states == [Standing::none(NONE_HERE.to_string())]
    }
}

/// One row of what is read: the kind of place, how often it is looked at, how many things, its
/// state and when it was last read. The count leads, where the row has a link, to the things.
fn watched_row(out: &mut String, row: &Row, now: i64) -> Out {
    let id = row.id.map_or(String::new(), |id| format!(" id=\"{id}\""));
    let said: Vec<String> = (row.states.iter())
        .map(|s| format!("<span class=\"dot{}\"></span>{}", s.dot, s.said))
        .collect();
    writeln!(
        out,
        "<div class=\"wr\"{id}><span>{}</span><span class=\"wh2 t2\">{}</span><span class=\"wn\">{}</span><span class=\"wc\">{}</span><span class=\"wl\">{}</span></div>",
        esc(&row.kind),
        esc(row.how),
        match &row.href {
            Some(href) => format!(
                "<a href=\"{href}\" aria-label=\"{}: {}\">{}</a>",
                esc(&row.kind),
                esc(&row.things),
                esc(&row.things)
            ),
            None => esc(&row.things),
        },
        said.join(" · "),
        row.last
            .map_or("<span class=\"none\">—</span>".to_string(), |t| {
                view::when(t, now)
            })
    )?;
    Ok(())
}

/// The table of what is read, group by group: under its group's name each row that says more than
/// that there is none here, then the rows that say only that, folded into one line of their names
/// (`Row::none_here`) with when they were read, as their rows' last read: one time, or from the
/// oldest to the latest, so a fold never hides that a reading is old.
fn read_table(out: &mut String, rows: &[Row], now: i64) -> Out {
    out.push_str("<div class=\"wt\">\n<div class=\"wr wh\" aria-hidden=\"true\"><span>Kind of place</span><span>How often</span><span class=\"wn\">Things</span><span>State</span><span class=\"wl\">Last read</span></div>\n");
    for group in [ON_THIS_MAC, IN_PROJECTS, BEYOND_THIS_MAC] {
        let of: Vec<&Row> = rows.iter().filter(|r| r.group == group).collect();
        if of.is_empty() {
            continue;
        }
        writeln!(out, "<p class=\"wg\">{group}</p>")?;
        let (none, said): (Vec<&Row>, Vec<&Row>) = of.into_iter().partition(|r| r.none_here());
        for row in said {
            watched_row(out, row, now)?;
        }
        if !none.is_empty() {
            let names: Vec<String> = (none.iter()).map(|r| esc(&r.kind)).collect();
            let times: BTreeSet<i64> = none.iter().filter_map(|r| r.last).collect();
            let at = match (times.first(), times.last()) {
                (Some(a), Some(b)) if a == b => format!(" at {}", view::when(*a, now)),
                (Some(a), Some(b)) => {
                    format!(" from {} to {}", view::when(*a, now), view::when(*b, now))
                }
                _ => String::new(),
            };
            writeln!(
                out,
                "<p class=\"kn\"><span class=\"dot\"></span><strong>None here, read in full{at}:</strong> {}</p>",
                names.join(" · ")
            )?;
        }
    }
    out.push_str("</div>\n");
    Ok(())
}

/// What is read, on the summary: the table by kind of place, on this Mac, in your projects and
/// beyond (`rows`).
fn watched_table(out: &mut String, r: &v1::Status, now: i64) -> Out {
    writeln!(
        out,
        "<section id=\"watched-here\">\n<div class=\"wsh\"><h2>{READ_TITLE}</h2><span class=\"n\">on this Mac, in your projects and beyond</span></div>"
    )?;
    read_table(out, &rows(r, &Links::summary(), now), now)?;
    out.push_str("</section>\n");
    Ok(())
}

/// The heading of what is read, on the summary.
const READ_TITLE: &str = "What is read";

/// What is read, as rows by kind of place, grouped as on this Mac, in your projects and beyond
/// this Mac: how often each is looked at, how many things, its state and when it was last read,
/// from the status alone, its links leading `from` the page it is drawn on. A row's state is one
/// of three: the faults of the status that name its kind (`Uncovered.watched_kinds`), linked to
/// "Could not be read", and only they are drawn as faults; else how it was read, "read in full"
/// and "none here" only where the status says its kind was read in full and fresh
/// (`WatchedKind.coverage` and `fresh`, `IntegrityReading`), and "not checked yet" with no
/// reading of it; else a plain count. A limit is never a row's fault: it is told once, at the end.
fn rows(r: &v1::Status, from: &Links, now: i64) -> Vec<Row> {
    // Whether a thing not covered is a fault or a limit is the status's word.
    let faults: Vec<&v1::Uncovered> = r.not_covered.iter().filter(|u| u.fault).collect();
    let m = r.this_mac.clone().unwrap_or_default();
    let kinds = r.watched.as_ref().map_or(&[][..], |w| &w.kinds[..]);
    let full = v1::Completeness::Full as i32;
    let t = r.vulnerabilities.clone();
    // Whether projects were looked for everywhere, or everywhere but in the folders this version
    // does not enter, when what is said of projects is said of the projects found.
    let found = t.as_ref().and_then(|t| t.projects_found.as_ref());
    let not_entered =
        |f: &v1::ProjectsFound| v1::Cause::try_from(f.cause) == Ok(v1::Cause::NotGiven);
    let walked = found.is_some_and(|f| f.all || not_entered(f));
    let in_found = found.is_some_and(|f| !f.all && not_entered(f));
    // The latest full check, whose readings of installed software the status gives.
    let check = (r.last_finished_run.as_ref())
        .and_then(|f| f.check.as_ref())
        .map(|c| c.started_at);
    // A fault is told in full under "Could not be read", its label naming that place before
    // what the row says.
    let told = |said: String| {
        let said = esc(&said);
        Standing::not(format!(
            "<a href=\"{}#{NOT_READ}\" aria-label=\"{NOT_READ_TITLE}: {said}\">{said}</a>",
            from.summary
        ))
    };
    // The faults of some causes, as one state of a row.
    let by = |ids: &[&str], said: &str| {
        (faults.iter())
            .any(|u| ids.contains(&u.id.as_str()))
            .then(|| told(said.to_string()))
    };
    let mut out = Vec::new();
    for (count, what, _) in covered::watched() {
        let thing = m.watched.iter().find(|w| w.what == what);
        let how = match thing.is_some_and(|w| w.how == "live") {
            true => "within seconds",
            false => "at full checks",
        };
        let n = thing.map(|w| w.count as i64);
        let key = match count {
            Count::Files(as_) => as_,
            Count::Installed(kind) => kind,
            Count::Dependencies => covered::DEPENDENCIES,
        };
        // A fault that names its kind; a fault that names none stays in its section alone. A
        // fault counts the places of its cause, of every kind, so the row gives no number.
        let mut faulted: Vec<Standing> = Vec::new();
        if faults
            .iter()
            .any(|u| u.watched_kinds.iter().any(|k| k == key))
        {
            faulted.push(told("not all can be read now".to_string()));
        }
        let mut things = n.map_or("—".to_string(), grouped);
        // The packages' own state, and beside it what the comparison found.
        let (mut read, mut beside, mut last) = (None, Vec::new(), None);
        if let Count::Dependencies = count {
            let data = [
                covered::VULNERABILITY_DATA_OLD.id,
                covered::VULNERABILITY_DATA_FIXABLE.id,
            ];
            faulted.extend(by(&data, "vulnerability data not current"));
            let t = t.clone().unwrap_or_default();
            if let Some(n) = n {
                things = grouped(n);
            }
            // At every check only where every project was compared in full, against data
            // current now, and projects were looked for everywhere; why one was not is a fault
            // above or a limit at the end.
            let current = (t.feeds.iter()).filter(|f| f.matched).all(|f| f.current);
            let all = crate::text::Matched::of(&t).all_compared() && walked && current;
            read = Some(match (t.matched_this_store, t.projects_compared, all) {
                (false, ..) => Standing::never("not compared yet"),
                (true, 0, _) => Standing::never("no project compared"),
                (true, _, true) => Standing::read("compared at every check"),
                (true, _, false) => Standing::read("compared"),
            });
            last = check.filter(|_| t.matched_this_store);
            let known: u64 = (t.affected_records_by_label.iter())
                .filter(|c| c.name != "malicious")
                .map(|c| c.count)
                .sum();
            if t.matched_this_store && known > 0 {
                beside.push(Standing::none(format!(
                    "<a href=\"{}{VULNERABILITIES}.html\">{}</a>",
                    from.details,
                    esc(&counted(
                        known as i64,
                        "known vulnerability",
                        "known vulnerabilities"
                    ))
                )));
                // "None used in attacks" rests on none being on the catalogue's list and the
                // catalogue being current, by the one rule the answers rest on; one that is used
                // is a finding, in the table of findings. Its fault is the list's download.
                if t.affected_exploited == 0 {
                    let read_at = r.threats.as_ref().and_then(|c| c.read_at);
                    let list = [covered::THREATS_UNREAD.id, covered::THREATS_FIXABLE.id];
                    let unknown = "whether any is used in attacks is not known";
                    beside.push(
                        match crate::vulnerabilities::catalogue_current_at(read_at, now) {
                            false => {
                                by(&list, unknown).unwrap_or_else(|| Standing::none(esc(unknown)))
                            }
                            true => Standing::read("none is known to be used in attacks"),
                        },
                    );
                }
            }
        }
        let read = read.unwrap_or_else(|| {
            // Whole only by the status's word for its kind; a kind kept in projects also needs
            // the projects looked for.
            let (whole, at) = match count {
                Count::Files(as_) => match kinds.iter().find(|k| k.kind == as_) {
                    Some(k) => (k.coverage == Some(full) && k.fresh, k.read_at),
                    None => (false, None),
                },
                Count::Installed(kind) => match installed_whole(r, kind) {
                    Some(whole) => (whole, check),
                    None => (false, None),
                },
                Count::Dependencies => (false, None),
            };
            last = at;
            // With no reading of it, a count proves nothing read.
            if at.is_none() {
                return Standing::never("not checked yet");
            }
            let in_projects = covered::in_projects(count);
            let whole = whole && (!in_projects || walked);
            let found = in_projects && in_found;
            match (n.unwrap_or(0) == 0, found, whole) {
                (true, true, true) => Standing::none("none in the projects found".to_string()),
                (true, false, true) => Standing::none(NONE_HERE.to_string()),
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
        let at = format!("{}{THIS_MAC}.html#{}", from.details, anchor(what));
        let group = match covered::in_projects(count) || matches!(count, Count::Dependencies) {
            true => IN_PROJECTS,
            false => ON_THIS_MAC,
        };
        out.push(Row {
            group,
            id: matches!(count, Count::Dependencies).then_some("vulnerabilities"),
            kind: capital(what),
            how,
            things,
            href: n.is_some().then_some(at),
            states,
            last,
        });
    }
    // Servers, checked only when the person runs the server check. A person with no servers is
    // not told about servers at all. Its faults are the status's: servers that could not be
    // opened, and those the last server check did not finish on. Else "checked" rests on the
    // status's count of servers the last server check read in full.
    let e = r.estate.clone().unwrap_or_default();
    let server_faults = [
        (&covered::SERVERS_NOT_OPENED, "could not be opened"),
        (&covered::SERVERS_NOT_CHECKED, "not checked last time"),
    ];
    let mut states: Vec<Standing> = Vec::new();
    for (cause, words) in server_faults {
        let n: u64 = (faults.iter().filter(|u| u.id == cause.id))
            .map(|u| u.count)
            .sum();
        if n > 0 {
            states.push(told(format!("{} {words}", grouped(n as i64))));
        }
    }
    if e.servers > 0 || !states.is_empty() {
        if states.is_empty() {
            states.push(match e.servers_checked_in_last_check {
                0 => Standing::never("not checked yet"),
                n if n == e.servers => Standing::read("checked at the last server check"),
                n => Standing::none(esc(&format!(
                    "{} checked at the last server check",
                    grouped(n as i64)
                ))),
            });
        }
        let listed = format!("{}{BEYOND}.html#servers", from.details);
        out.push(Row {
            group: BEYOND_THIS_MAC,
            id: None,
            kind: "Servers you log in to over SSH".to_string(),
            how: "when you run the server check",
            things: grouped(e.servers as i64),
            href: Some(listed),
            states,
            last: e.server_check_at,
        });
    }
    out
}

/// What is read on this Mac and in its projects, as an index of the page of this Mac: the rows of
/// the summary's table, every count and name leading to its kind's section here.
pub(crate) fn read_index(out: &mut String, r: &v1::Status, now: i64) -> Out {
    let rows: Vec<Row> = (rows(r, &Links::details(), now).into_iter())
        .filter(|row| row.group != BEYOND_THIS_MAC)
        .collect();
    out.push_str("<section id=\"read-here\">\n<div class=\"wsh\"><h2>What is read here</h2><span class=\"n\">each kind of place, with its section below</span></div>\n");
    read_table(out, &rows, now)?;
    out.push_str("</section>\n");
    Ok(())
}

/// Whether the latest full check read a kind of installed software in full, by the status's
/// readings of it: `None` with no reading of it, else whether every one is full.
fn installed_whole(r: &v1::Status, kind: &str) -> Option<bool> {
    let of: Vec<&v1::IntegrityReading> = (r.integrity.iter().flat_map(|i| &i.readings))
        .filter(|i| i.kind == kind)
        .collect();
    let full = v1::Completeness::Full as i32;
    (!of.is_empty()).then(|| of.iter().all(|i| i.completeness == full))
}

/// The anchor of what could not be read, on the summary.
pub const NOT_READ: &str = "not-read";
/// Its heading.
const NOT_READ_TITLE: &str = "Could not be read";

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

/// What is told apart from a thing's words, as safe HTML: each example the status gives with what
/// its source said, cut as the status gives it, then what sources said of it, such as why a
/// download failed; and last, how many things it names past those examples, as the terminal
/// counts them.
pub(crate) fn apart(u: &v1::Uncovered) -> Vec<String> {
    let mut out: Vec<String> = (u.examples.iter())
        .map(|e| {
            let name = Name::given(&e.name_text).html();
            match &e.reason_text {
                Some(r) => format!("{name}: {}", Said::given(r).html()),
                None => name,
            }
        })
        .collect();
    out.extend(u.value_text.as_deref().map(|v| Said::given(v).html()));
    let more = u.count.saturating_sub(u.examples.len() as u64);
    if !u.examples.is_empty() && more > 0 {
        out.push(format!(
            "<span class=\"muted\">and {} more</span>",
            grouped(more as i64)
        ));
    }
    out
}

/// At most this many readings are named under a list that is not whole.
const GAPS_SHOWN: usize = 3;

/// What a list cannot claim, as safe HTML, from the latest readings that fill it: `None` when
/// there is at least one and every one is full and fresh, that is taken by the latest check and
/// dated no later than now (`store::age`); else a sentence naming each one that is not, with why
/// and when it was last read in full, and `extra`, what else the list rests on that is not
/// current, each already safe HTML. A list states that nothing is there only when this is `None`
/// (`absent`).
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
                // What the reader's source said, given whole: cut where it is printed.
                (_, Some(reason)) => Said::of(reason).html(),
                (_, None) => "not read in full".to_string(),
            };
            let last = r.last_full.map_or("never read in full".to_string(), |at| {
                format!("last read in full {}", view::when(at, now))
            });
            format!("{} ({why}; {last})", esc(&r.kind))
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

/// Writes what a list rests on when it is not whole, as safe HTML, and, for an empty list, that
/// nothing is there only when it is (`unread`).
fn coverage_of_list(out: &mut String, unread: Option<&str>, empty: bool, absent: &str) {
    match unread {
        // What `unread` says, whose sources' words went through the printer.
        Some(said) => {
            out.push_str("<p class=\"muted\">");
            out.push_str(said);
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

/// The top of a page of details for a person: its title, and under it a line already safe HTML,
/// such as the times it rests on (`view::when`).
fn top(title: &str, meta: &str) -> String {
    let mut out = view::head(title);
    out.push_str(BACK);
    out.push_str(&format!(
        "<header>\n<h1>{}</h1>\n<p class=\"meta\">{}</p>\n</header>\n",
        esc(title),
        meta
    ));
    out
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
    out.push_str(&format!(
        "<li><a href=\"{COVERAGE}.html\">{COVERAGE_TITLE}: every kind of reading that was not full, with why</a></li>\n"
    ));
    out.push_str("</ul>\n</section>\n");
    out.push_str(FOOT);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::covered::YOU;

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
        // A watcher's failure is a fault of Immunity Core's own work: said once, under the line,
        // as the terminal says it; the line says nothing of how much is read or of the failure,
        // and the failure is never counted as something that could not be read.
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
            assert!(!failed.contains("could not be read"), "{failed}");
        }
    }

    /// The band of a page in parts: the line under the headline, each `!` line but the count, in
    /// order, and the line that counts what could not be read, when there is one.
    fn band_drawn(page: &str) -> (String, Vec<String>, Option<String>) {
        let mut sub = page.split("<p class=\"sub\">").nth(1).unwrap().to_string();
        sub.truncate(sub.find("</p>").unwrap());
        let lines = (page.split("<p class=\"sub fault\">").skip(1))
            .map(|b| b[..b.find("</p>").unwrap()].to_string());
        let (count, own): (Vec<String>, Vec<String>) =
            lines.partition(|l| l.starts_with(&format!("! <a href=\"#{NOT_READ}\">")));
        assert!(count.len() <= 1, "{page}");
        (sub, own, count.into_iter().next())
    }

    /// The pages and the text agree, as values, and the band says less than the text of nothing:
    /// for every case of the watcher, a check not fresh with and without findings, and a status of
    /// real size with faults and with only limits, the line under the headline holds the state the
    /// default status decides (`overview::told`), and every fault of Immunity Core's own work is a
    /// `!` line of its own, as it was, in order, each with its own words, what its source said, its
    /// command and its advice; every other fault is a reading that failed, out of the band's words
    /// and counted on one `!` line, which leads to "Could not be read" and says how many the person
    /// can fix. The state is said
    /// once, the ring is drawn only while a fault stands, and a watcher that is starting is never
    /// said to be off. After `immunity on`, a job in place with no watcher and none restarting is
    /// off and not by `immunity off`, and never calm.
    #[test]
    fn the_band_says_each_state_in_its_words_and_counts_each_reading_that_failed_as_the_text_lists_them()
     {
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
        // Readings that failed of the event level: one that records nothing, and one that lost
        // program starts since the latest check.
        let level = |state: v1::CollectorState, lost: u64| {
            let mut s = calm();
            s.event_level = Some(v1::EventLevel {
                state: state as i32,
                said_text: Some("an invented <line>".to_string()),
                lost: Some(v1::Span {
                    since_check: lost,
                    ..Default::default()
                }),
                ..Default::default()
            });
            s
        };
        let others = [
            (None, level(v1::CollectorState::Failing, 0)),
            (None, level(v1::CollectorState::Running, 3)),
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
            let (sub, lines, count) = band_drawn(&page);
            let told = crate::overview::told(&s, &TERMINAL);
            // The state under the headline, then each fault of Immunity Core's own work on a `!`
            // line of its own, in the text's order: its words, what its source said, its command
            // and its advice, each where it follows.
            let own: Vec<&crate::overview::Fault> = (told.faults.iter())
                .filter(|f| f.about() == Of::State)
                .collect();
            assert_eq!(lines.len(), own.len(), "{page}");
            let state = (told.state.iter()).map(|(w, c)| ((w.as_str(), None, "", *c, None), false));
            let parts = own.iter().map(|f| (f.parts(), f.said_is_ours()));
            let drawn = (told.state.iter().map(|_| sub.as_str()))
                .chain(lines.iter().map(|l| l.strip_prefix("! ").unwrap()));
            for (((words, said, tail, c, advice), ours), line) in state.chain(parts).zip(drawn) {
                let said = said.map(|s| match ours {
                    true => esc(s),
                    false => crate::secrets::quoted_html(s),
                });
                let command = c.map(|c| format!("<span class=\"mono\">{}</span>", esc(c)));
                let mut at = 0;
                for piece in [
                    Some(esc(words)),
                    said,
                    Some(esc(tail)),
                    command,
                    advice.map(esc),
                ]
                .into_iter()
                .flatten()
                {
                    let found = line[at..].find(&piece);
                    assert!(found.is_some(), "{piece} after {at}: {page}");
                    at += found.unwrap() + piece.len();
                }
            }
            // The state is said once.
            if let Some((words, _)) = &told.state {
                assert_eq!(sub.matches(&esc(words)).count(), 1, "{page}");
            }
            // Every other fault is out of the band's words, and counted under them.
            let failed: Vec<&crate::overview::Fault> = (told.faults.iter())
                .filter(|f| f.about() != Of::State)
                .collect();
            for f in &failed {
                let (words, ..) = f.parts();
                assert!(!page.contains(&esc(words)), "{words}: {page}");
            }
            // Counted by the things: a cause as many as its title counts, at least one, and each
            // other reading one.
            let things = |u: &&v1::Uncovered| u.count.max(1);
            let causes: Vec<&v1::Uncovered> = s.not_covered.iter().filter(|u| u.fault).collect();
            let readings = (failed.iter().filter(|f| f.about() == Of::Reading)).count() as u64;
            let n = causes.iter().map(things).sum::<u64>() + readings;
            let yours: u64 = (causes.iter().filter(|u| u.who == YOU)).map(things).sum();
            let wanted = (!failed.is_empty()).then(|| {
                let n = counted(n as i64, "thing", "things");
                let yours = match yours {
                    0 => String::new(),
                    y => format!(", {y} you can fix"),
                };
                format!("! <a href=\"#{NOT_READ}\">{n} could not be read{yours}</a>")
            });
            assert_eq!(count, wanted, "{page}");
            // Of the status of real size: the ring only while a fault stands, by the headline
            // that says so.
            if !s.not_covered.is_empty() {
                let calm = s.headline == v1::Headline::Calm as i32;
                assert_eq!(page.contains(GLYPH_PART), !calm, "{page}");
                assert_eq!(own.is_empty() && count.is_none(), calm, "{page}");
            }
            if let Some(case) = case {
                let band = format!("{sub} {lines:?} {count:?}");
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
                NONE_KNOWN,
            );
            out
        };
        let full = reading("full", run);
        assert!(said(&[&full], &[]).contains(NONE_KNOWN));
        for not in [
            reading("partial", run),
            reading("none", run),
            reading("full", run - 1),
            reading("full", now + crate::store::AHEAD_ALLOWED + 1),
        ] {
            let out = said(&[&full, &not], &[]);
            assert!(
                !out.contains(NONE_KNOWN)
                    && out.contains("invented things")
                    && out.contains("last read in full"),
                "{out}"
            );
        }
        assert!(!said(&[], &[]).contains(NONE_KNOWN));
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
        assert!(!out.contains(NONE_KNOWN) && out.contains(&old[0]), "{out}");
        // Without any finished check, nothing is fresh.
        let mut out = String::new();
        coverage_of_list(
            &mut out,
            unread(&[&full], None, now, &[]).as_deref(),
            true,
            NONE_KNOWN,
        );
        assert!(!out.contains(NONE_KNOWN), "{out}");
        // A list that is not empty is not told as empty either way.
        let mut out = String::new();
        coverage_of_list(&mut out, None, false, NONE_KNOWN);
        assert!(out.is_empty());
    }

    /// What a list of servers says when it is empty, as the page beyond this Mac says it.
    const NONE_KNOWN: &str = "None known.";

    /// The part of a page from the section with `id` to its end, or nothing.
    pub(super) fn section_of<'a>(html: &'a str, id: &str) -> &'a str {
        let rest = html
            .find(&format!("<section id=\"{id}\">"))
            .map_or("", |i| &html[i..]);
        &rest[..rest.find("</section>").unwrap_or(rest.len())]
    }

    /// Nothing is hidden and nothing is told twice: every thing not covered, for every cause of
    /// the catalogue, is on the pages once, a fault under "Could not be read", marked where the
    /// person can fix it, and a limit in the collapsed section at the end, by the status's `fault`
    /// alone; a limit's names are there only, and stay text.
    #[test]
    fn every_thing_not_covered_is_on_the_pages_once_a_fault_in_its_section_a_limit_at_the_end() {
        let now = 1_800_000_000;
        let mut r = v1::Status {
            answered_at: now,
            not_covered: (covered::CAUSES.iter())
                .map(|c| {
                    crate::status::uncovered_message(&covered::Uncovered {
                        examples: vec![covered::Example::named(format!("<b>{}</b>", c.id))],
                        ..covered::Uncovered::new(c, 1)
                    })
                })
                .collect(),
            ..Default::default()
        };
        // Both sorts of every cause: the status's word, then its opposite.
        for flip in [false, true] {
            for u in &mut r.not_covered {
                u.fault = (u.class == v1::Cause::Failed as i32) != flip;
            }
            let pages = view::pages(&r, &view::Answers::none(), now).unwrap();
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
                let home = match u.fault {
                    false => limits,
                    true => section_of(summary, NOT_READ),
                };
                assert!(
                    home.contains(&id) && home.contains(&name),
                    "{} flip {flip}",
                    u.id
                );
                // A fault the person can fix says so beside it.
                if u.fault {
                    let article = &home[home.find(&id).unwrap()..];
                    let article = &article[..article.find("</article>").unwrap()];
                    let you = article.contains(">You can fix</p>");
                    assert_eq!(you, u.who == YOU, "{article}");
                }
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
    }

    /// The state and the last read of the row of what is read whose kind starts with `what`, as
    /// a row is drawn, folded or not.
    fn row(r: &v1::Status, what: &str, now: i64) -> (String, String) {
        let rows = rows(r, &Links::summary(), now);
        let row = (rows.iter())
            .find(|row| row.kind.starts_with(what))
            .unwrap_or_else(|| panic!("{what}"));
        let mut out = String::new();
        watched_row(&mut out, row, now).unwrap();
        let row = out.trim_end();
        let cell = &row[row.find("<span class=\"wc\">").unwrap() + 17..];
        let (state, last) = cell.split_once("</span><span class=\"wl\">").unwrap();
        (
            state.to_string(),
            last.trim_end_matches("</span></div>").to_string(),
        )
    }

    /// A status with this Mac's things counted and the status's word for each kind of files.
    fn watched_status(things: &[(&str, u64)], kinds: Vec<v1::WatchedKind>) -> v1::Status {
        v1::Status {
            this_mac: Some(v1::ThisMac {
                watched: (things.iter())
                    .map(|(what, count)| v1::WatchedThing {
                        what: what.to_string(),
                        count: *count,
                        how: "hourly".to_string(),
                    })
                    .collect(),
                ..Default::default()
            }),
            watched: Some(v1::WatchedPlaces {
                kinds,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    const CALM: &str = "<span class=\"dot calm\"></span>";
    const NEVER: &str = "<span class=\"dot off\"></span>";

    /// No false calm: a row of watched files says "read in full" and "none here" only where the
    /// status says its kind was read in full and fresh (`WatchedKind.coverage` and `fresh`),
    /// never because it counts nothing, and a kind kept in projects only where projects were
    /// looked for. A row is drawn as a fault only by a fault of the status that names its kind
    /// (`Uncovered.watched_kinds`), and then never says it was read in full; the fault is linked
    /// to where it is told, "Could not be read". A row with no reading is "not checked yet".
    #[test]
    fn a_row_says_read_in_full_or_none_here_only_by_its_kind_and_never_beside_a_fault_of_it() {
        let now = 1_800_000_000;
        let what = "Shell startup files";
        let kind = |coverage: v1::Completeness, fresh: bool| v1::WatchedKind {
            kind: crate::watched::PROFILE.to_string(),
            coverage: Some(coverage as i32),
            fresh,
            read_at: Some(now - 40),
            ..Default::default()
        };
        let state = |count: u64, k: Option<v1::WatchedKind>| {
            let r = watched_status(&[("shell startup files", count)], k.into_iter().collect());
            row(&r, what, now)
        };
        let full = v1::Completeness::Full;
        assert_eq!(
            state(0, Some(kind(full, true))),
            (
                "<span class=\"dot\"></span>none here".to_string(),
                view::when(now - 40, now)
            )
        );
        assert_eq!(
            state(4, Some(kind(full, true))).0,
            format!("{CALM}read in full")
        );
        for not in [kind(full, false), kind(v1::Completeness::Partial, true)] {
            assert_eq!(state(0, Some(not.clone())).0, format!("{CALM}read"));
            assert_eq!(state(4, Some(not)).0, format!("{CALM}read"));
        }
        assert_eq!(
            state(0, None),
            (
                format!("{NEVER}not checked yet"),
                "<span class=\"none\">—</span>".to_string()
            )
        );
        // A fault of the status that names the kind: the row is that fault, linked to where it
        // is told; one that names another kind, or none, leaves the row as it was read.
        let fault = |who: &str, kinds: &[&str]| v1::Uncovered {
            id: "could-not-read".to_string(),
            who: who.to_string(),
            count: 2,
            fault: true,
            watched_kinds: kinds.iter().map(|k| k.to_string()).collect(),
            ..Default::default()
        };
        let with = |u: v1::Uncovered| {
            let mut r = watched_status(&[("shell startup files", 0)], vec![kind(full, true)]);
            r.not_covered = vec![u];
            row(&r, what, now).0
        };
        assert_eq!(
            with(fault("nothing", &[crate::watched::PROFILE])),
            format!(
                "<span class=\"dot off look\"></span><a href=\"#{NOT_READ}\" aria-label=\"{NOT_READ_TITLE}: not all can be read now\">not all can be read now</a>"
            )
        );
        // A cause of ten places, one of them of this kind: the row says no number of them.
        let wide = v1::Uncovered {
            count: 10,
            ..fault("nothing", &[crate::watched::PROFILE, crate::watched::SSH])
        };
        assert!(!with(wide.clone()).contains("10"), "{}", with(wide));
        assert_eq!(
            with(fault(YOU, &[crate::watched::PROFILE])),
            with(fault("nothing", &[crate::watched::PROFILE]))
        );
        assert_eq!(
            with(fault("nothing", &[crate::watched::SSH])),
            "<span class=\"dot\"></span>none here"
        );
        assert_eq!(
            with(fault("nothing", &[])),
            "<span class=\"dot\"></span>none here"
        );
        // A limit names no row.
        let limit = v1::Uncovered {
            fault: false,
            ..fault("nothing", &[crate::watched::PROFILE])
        };
        assert_eq!(with(limit), "<span class=\"dot\"></span>none here");
        // The hooks in projects, read in full and fresh, while the search for projects failed.
        let hooks = v1::WatchedKind {
            kind: crate::watched::HOOK.to_string(),
            ..kind(full, true)
        };
        let mut r = watched_status(&[("git hooks in projects", 0)], vec![hooks]);
        let found = |all, cause: v1::Cause| v1::VulnerabilityTotals {
            projects_found: Some(v1::ProjectsFound {
                all,
                cause: cause as i32,
                ..Default::default()
            }),
            ..Default::default()
        };
        r.vulnerabilities = Some(found(false, v1::Cause::Failed));
        assert_eq!(row(&r, "Git hooks", now).0, format!("{CALM}read"));
        r.vulnerabilities = Some(found(false, v1::Cause::NotGiven));
        assert_eq!(
            row(&r, "Git hooks", now).0,
            "<span class=\"dot\"></span>none in the projects found"
        );
        r.vulnerabilities = Some(found(true, v1::Cause::Unspecified));
        assert_eq!(
            row(&r, "Git hooks", now).0,
            "<span class=\"dot\"></span>none here"
        );
    }

    /// A row of installed software is read in full by the status's reading of its kind, last read
    /// when the latest full check began; and the packages are compared at every check only where
    /// every project was compared against data current now, orange only by a fault of the data,
    /// and say none of their known vulnerabilities is used in attacks only while none is on the
    /// catalogue's list and the catalogue is current by the rule the answers rest on.
    #[test]
    fn installed_software_and_the_packages_are_said_read_by_the_status_s_own_counts() {
        let now = 1_800_000_000;
        let mut r = watched_status(
            &[("Homebrew packages", 7), (covered::DEPENDENCIES, 9)],
            vec![],
        );
        r.last_finished_run = Some(v1::FinishedCheck {
            check: Some(v1::CheckMark {
                started_at: now - 60,
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(
            row(&r, "Homebrew", now).0,
            format!("{NEVER}not checked yet")
        );
        let reading = |c: v1::Completeness| v1::Integrity {
            readings: vec![v1::IntegrityReading {
                kind: crate::integrity::KEGS.to_string(),
                completeness: c as i32,
                ..Default::default()
            }],
            ..Default::default()
        };
        r.integrity = Some(reading(v1::Completeness::Full));
        assert_eq!(
            row(&r, "Homebrew", now),
            (format!("{CALM}read in full"), view::when(now - 60, now))
        );
        r.integrity = Some(reading(v1::Completeness::Partial));
        assert_eq!(row(&r, "Homebrew", now).0, format!("{CALM}read"));

        let packages = |r: &v1::Status| row(r, "Packages your projects", now).0;
        assert_eq!(packages(&r), format!("{NEVER}not compared yet"));
        let feed = |current| v1::FeedFreshness {
            matched: true,
            current,
            ..Default::default()
        };
        let compared = v1::VulnerabilityTotals {
            matched_this_store: true,
            projects_compared: 2,
            projects_found: Some(v1::ProjectsFound {
                all: true,
                ..Default::default()
            }),
            feeds: vec![feed(true)],
            affected_records: 3,
            affected_records_by_label: vec![v1::Count {
                name: "high".to_string(),
                count: 3,
            }],
            ..Default::default()
        };
        r.vulnerabilities = Some(compared.clone());
        r.threats = Some(v1::Threats {
            read_at: Some(now - 60),
            ..Default::default()
        });
        let link = format!(
            "<span class=\"dot\"></span><a href=\"{DETAILS}/{VULNERABILITIES}.html\">3 known vulnerabilities</a>"
        );
        assert_eq!(
            packages(&r),
            format!(
                "{CALM}compared at every check · {link} · {CALM}none is known to be used in attacks"
            )
        );
        // A feed not current, a package that cannot be told: compared, not at every check.
        for t in [
            v1::VulnerabilityTotals {
                feeds: vec![feed(true), feed(false)],
                ..compared.clone()
            },
            v1::VulnerabilityTotals {
                unknown_packages: 1,
                ..compared.clone()
            },
        ] {
            r.vulnerabilities = Some(t);
            assert!(
                packages(&r).starts_with(&format!("{CALM}compared · ")),
                "{}",
                packages(&r)
            );
        }
        r.vulnerabilities = Some(compared.clone());
        // One on the catalogue's list: nothing is said of use in attacks here.
        r.vulnerabilities = Some(v1::VulnerabilityTotals {
            affected_exploited: 1,
            ..compared.clone()
        });
        assert!(!packages(&r).contains("attacks"), "{}", packages(&r));
        // A catalogue not current: not known, whatever its latest attempt said.
        r.vulnerabilities = Some(compared.clone());
        r.threats = Some(v1::Threats {
            read_at: Some(now - crate::threats::CURRENT_FOR - 1),
            outcome: v1::FeedOutcome::Unchanged as i32,
            ..Default::default()
        });
        assert!(
            packages(&r).ends_with(
                "<span class=\"dot\"></span>whether any is used in attacks is not known"
            ),
            "{}",
            packages(&r)
        );
        // Orange only by a fault of the data the packages are compared with.
        r.not_covered = vec![v1::Uncovered {
            id: covered::VULNERABILITY_DATA_OLD.id.to_string(),
            fault: true,
            ..Default::default()
        }];
        assert!(
            packages(&r).starts_with("<span class=\"dot off look\"></span><a href="),
            "{}",
            packages(&r)
        );
    }

    /// No false calm in the fold: a kind is folded into "None here, read in full" only where all
    /// its row says is that; a kind with a fault, a reading short of full or not fresh, no reading,
    /// or things in it keeps a row of its own.
    #[test]
    fn a_kind_is_folded_into_none_here_only_where_its_row_says_nothing_else() {
        let now = 1_800_000_000;
        let kind = |as_: &str, fresh: bool| v1::WatchedKind {
            kind: as_.to_string(),
            coverage: Some(v1::Completeness::Full as i32),
            fresh,
            read_at: Some(now - 40),
            ..Default::default()
        };
        let (profile, ssh) = ("Shell startup files", "SSH files");
        // Where each kind is drawn: folded, or in a row of its own.
        let drawn = |r: &v1::Status, what: &str| {
            let mut out = String::new();
            read_table(&mut out, &rows(r, &Links::summary(), now), now).unwrap();
            let folded = (out.lines().filter(|l| l.starts_with("<p class=\"kn\">")))
                .any(|l| l.contains(what));
            let row = (out.lines().filter(|l| l.starts_with("<div class=\"wr\">")))
                .any(|l| l.contains(&format!("<span>{what}</span>")));
            assert_ne!(folded, row, "{what}: {out}");
            folded
        };
        let things = [("shell startup files", 0), ("SSH files", 0)];
        let mut r = watched_status(
            &things,
            vec![
                kind(crate::watched::PROFILE, true),
                kind(crate::watched::SSH, false),
            ],
        );
        assert!(drawn(&r, profile));
        assert!(!drawn(&r, ssh));
        // No reading of it.
        let none = watched_status(&things, vec![kind(crate::watched::SSH, true)]);
        assert!(!drawn(&none, profile) && drawn(&none, ssh));
        // Things in it.
        let full = watched_status(
            &[("shell startup files", 2)],
            vec![kind(crate::watched::PROFILE, true)],
        );
        assert!(!drawn(&full, profile));
        // A fault that names it.
        r.not_covered = vec![v1::Uncovered {
            id: "could-not-read".to_string(),
            fault: true,
            watched_kinds: vec![crate::watched::PROFILE.to_string()],
            ..Default::default()
        }];
        assert!(!drawn(&r, profile));
    }

    /// A folded line carries its time: when its kinds were read, as their rows' last read would
    /// say it, once when they were read at the same time and from the oldest to the latest when
    /// not, so a day-old reading never reads as one of now.
    #[test]
    fn a_folded_line_carries_when_its_kinds_were_read() {
        let now = 1_800_000_000;
        let kind = |as_: &str, at: i64| v1::WatchedKind {
            kind: as_.to_string(),
            coverage: Some(v1::Completeness::Full as i32),
            fresh: true,
            read_at: Some(at),
            ..Default::default()
        };
        let fold = |old: i64| {
            let r = watched_status(
                &[("shell startup files", 0), ("SSH files", 0)],
                vec![
                    kind(crate::watched::PROFILE, old),
                    kind(crate::watched::SSH, now - 40),
                ],
            );
            let mut out = String::new();
            read_table(&mut out, &rows(&r, &Links::summary(), now), now).unwrap();
            let line = out.lines().find(|l| l.starts_with("<p class=\"kn\">"));
            line.unwrap_or_else(|| panic!("{out}")).to_string()
        };
        let (old, new) = (view::when(now - 86_400, now), view::when(now - 40, now));
        assert!(
            fold(now - 40).contains(&format!(
                "<strong>None here, read in full at {new}:</strong>"
            )),
            "{}",
            fold(now - 40)
        );
        assert!(
            fold(now - 86_400).contains(&format!(
                "<strong>None here, read in full from {old} to {new}:</strong>"
            )),
            "{}",
            fold(now - 86_400)
        );
    }

    /// The page of this Mac opens with what is read on it and in its projects: the summary's own
    /// rows, each leading within the page, so the two never say a kind apart; servers are on the
    /// page of what is beyond this Mac.
    #[test]
    fn the_index_of_this_mac_is_the_summary_s_rows_of_this_mac_and_its_projects() {
        let now = 1_800_000_000;
        let mut r = watched_status(
            &[("shell startup files", 3), ("git hooks in projects", 0)],
            vec![v1::WatchedKind {
                kind: crate::watched::PROFILE.to_string(),
                read_at: Some(now - 40),
                ..Default::default()
            }],
        );
        r.estate = Some(v1::Estate {
            servers: 2,
            ..Default::default()
        });
        r.not_covered = vec![v1::Uncovered {
            id: "could-not-read".to_string(),
            fault: true,
            watched_kinds: vec![crate::watched::PROFILE.to_string()],
            ..Default::default()
        }];
        let pages = view::pages(&r, &view::Answers::none(), now).unwrap();
        let page = |name: &str| &pages.iter().find(|(n, _)| n == name).unwrap().1;
        let lines = |html: &str, id: &str| -> Vec<String> {
            (section_of(html, id).lines())
                .filter(|l| l.starts_with("<div class=\"wr\""))
                .map(str::to_string)
                .collect()
        };
        let summary = lines(page(view::SUMMARY), "watched-here");
        let this_mac = page(&format!("{DETAILS}/{THIS_MAC}.html"));
        let index = lines(this_mac, "read-here");
        let from_details: Vec<String> = (summary.iter())
            .filter(|l| !l.contains("Servers you log in to"))
            .map(|l| {
                l.replace(&format!("href=\"{DETAILS}/"), "href=\"").replace(
                    &format!("href=\"#{NOT_READ}\""),
                    &format!("href=\"../{}#{NOT_READ}\"", view::SUMMARY),
                )
            })
            .collect();
        assert!(
            summary.len() > from_details.len() && !index.is_empty(),
            "{summary:?}"
        );
        assert_eq!(index, from_details);
        let at = |id: &str| this_mac.find(&format!("<section id=\"{id}\"")).unwrap();
        assert!(at("read-here") < at("no-answer"), "{this_mac}");
    }
}
