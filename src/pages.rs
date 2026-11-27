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

pub(crate) mod findings_table;
pub(crate) mod rules;
pub(crate) mod this_mac;
pub(crate) mod vulnerabilities;

use crate::contract::v1;
use crate::covered::{self, Count, YOU};
use crate::secrets::{Name, Said};
use crate::view::{self, DETAILS, FOOT, Latest, Out, counted, esc, esc_said, utc, utc_or};
use crate::{beyond, servers};
use rusqlite::Connection;
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

/// The summary page, a report read from the top: the state in the panel's words, with one line
/// on what it rests on; the findings as a table, open, answered and all, each row opening in
/// place to its evidence as `immunity finding` gives it; what is watched, area by area, with its
/// state and when it was last read; "As it happens", every program start checked against
/// published rules (`happens.rs`); the faults the person can fix; once, collapsed, what this
/// version does not read here (`not_read_here.rs`); and a line of links to the other pages.
/// Drawn from what the commands answer alone, the status first, so the two agree.
pub fn summary(
    r: &v1::Status,
    answers: &view::Answers,
    now: i64,
) -> Result<String, Box<dyn Error>> {
    let mut out = view::head("What needs a look").replacen("<body>", "<body class=\"summary\">", 1);
    // Whether a thing not covered is a fault or a limit is the status's word.
    let (faults, limits): (Vec<&v1::Uncovered>, Vec<&v1::Uncovered>) =
        r.not_covered.iter().partition(|u| u.fault);
    state(&mut out, r, now)?;
    findings_table::table(&mut out, answers, now)?;
    watched_table(&mut out, r, &faults, now)?;
    crate::happens::draw(&mut out, r, &answers.rules, &answers.findings, now)?;
    you_can_fix(&mut out, &fixable(&faults))?;
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

/// What is watched, as a table by kind of place, grouped as on this Mac, in your projects and
/// beyond this Mac: how often each is looked at, how many things, its state and when it was last
/// read, from the status alone. A row's state is one of three: the faults of the status that name
/// its kind (`Uncovered.watched_kinds`), linked to where they are told, and only they are drawn as
/// faults; else how it was read, "read in full" and "none here" only where the status says its
/// kind was read in full and fresh (`WatchedKind.coverage` and `fresh`, `IntegrityReading`), and
/// "not checked yet" with no reading of it; else a plain count. A limit is never a row's fault:
/// it is told once, at the end. Then one line: how many faults on this Mac nothing the person
/// does changes, as a link to the page that names each.
fn watched_table(out: &mut String, r: &v1::Status, faults: &[&v1::Uncovered], now: i64) -> Out {
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
    // Where a fault is told in full: "You can fix", or the page of what could not be read, its
    // label naming that place before what the row says.
    let told = |of: &[&&v1::Uncovered], said: String| {
        let (href, at) = match of.iter().all(|u| u.who == YOU) {
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
    // The faults of some causes, as one state of a row.
    let by = |ids: &[&str], said: &str| {
        let of: Vec<&&v1::Uncovered> = faults
            .iter()
            .filter(|u| ids.contains(&u.id.as_str()))
            .collect();
        (!of.is_empty()).then(|| told(&of, said.to_string()))
    };
    writeln!(
        out,
        "<section id=\"watched-here\">\n<div class=\"wsh\"><h2>What is watched</h2><span class=\"n\">on this Mac, in your projects and beyond</span></div>\n<div class=\"wt\">\n<div class=\"wr wh\" aria-hidden=\"true\"><span>Kind of place</span><span>How often</span><span class=\"wn\">Things</span><span>State</span><span class=\"wl\">Last read</span></div>"
    )?;
    let mut on_mac = String::new();
    let mut in_projects = String::new();
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
        // The faults that name its kind; a fault that names none stays in its section alone.
        let of: Vec<&&v1::Uncovered> = (faults.iter())
            .filter(|u| u.watched_kinds.iter().any(|k| k == key))
            .collect();
        let mut faulted: Vec<Standing> = Vec::new();
        if !of.is_empty() {
            let things: u64 = of.iter().map(|u| u.count.max(1)).sum();
            faulted.push(told(
                &of,
                format!("{} can't be read now", grouped(things as i64)),
            ));
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
                    "<a href=\"{DETAILS}/{VULNERABILITIES}.html\">{}</a>",
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
            last,
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
            let of: Vec<&&v1::Uncovered> = faults.iter().filter(|u| u.id == cause.id).collect();
            states.push(told(&of, format!("{} {words}", grouped(n as i64))));
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
        out.push_str("<p class=\"wg\">Beyond this Mac</p>\n");
        let listed = format!("{DETAILS}/{BEYOND}.html#servers");
        watched_row(
            out,
            None,
            (
                "Servers you log in to over SSH",
                "when you run the server check",
            ),
            (&grouped(e.servers as i64), Some(listed.as_str())),
            &states,
            None,
            now,
        )?;
    }
    out.push_str("</div>\n");
    let failed = failed_here(faults).len();
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

/// Whether the latest full check read a kind of installed software in full, by the status's
/// readings of it: `None` with no reading of it, else whether every one is full.
fn installed_whole(r: &v1::Status, kind: &str) -> Option<bool> {
    let of: Vec<&v1::IntegrityReading> = (r.integrity.iter().flat_map(|i| &i.readings))
        .filter(|i| i.kind == kind)
        .collect();
    let full = v1::Completeness::Full as i32;
    (!of.is_empty()).then(|| of.iter().all(|i| i.completeness == full))
}

/// The anchor of what could not be read on this Mac, on the page of what is watched.
pub const NOT_READ: &str = "not-read";
/// Its heading.
const NOT_READ_TITLE: &str = "Could not be read on this Mac";

/// The faults the person can do something about, told under "You can fix".
fn fixable<'a>(faults: &[&'a v1::Uncovered]) -> Vec<&'a v1::Uncovered> {
    faults.iter().copied().filter(|u| u.who == YOU).collect()
}

/// The faults nothing the person does changes, such as a reading or a download that failed, told
/// under "Could not be read on this Mac". With `fixable`, every fault, each once.
fn failed_here<'a>(faults: &[&'a v1::Uncovered]) -> Vec<&'a v1::Uncovered> {
    faults.iter().copied().filter(|u| u.who != YOU).collect()
}

/// The faults the person can fix, one cause beside another: what it is, the examples the status
/// gives as data, and Immunity Core's advice. A limit with advice is told among the limits.
fn you_can_fix(out: &mut String, fixable: &[&v1::Uncovered]) -> Out {
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
                esc(&u.id),
                esc(&u.title)
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
                esc(&u.meaning),
                esc(&u.advice)
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

/// One thing not covered, in full: its title, where, what it means and what to do.
fn uncovered(out: &mut String, u: &v1::Uncovered) -> Out {
    writeln!(
        out,
        "<article class=\"item\" id=\"{}\">\n<h3>{}</h3>",
        esc(&u.id),
        esc(&u.title)
    )?;
    let apart = apart(u);
    if !apart.is_empty() {
        out.push_str("<ul class=\"readings mono\">\n");
        for item in &apart {
            writeln!(out, "<li>{item}</li>")?;
        }
        out.push_str("</ul>\n");
    }
    writeln!(
        out,
        "<p>{}</p>\n<p class=\"advice\">{}</p>\n</article>",
        esc(&u.meaning),
        esc(&u.advice)
    )?;
    Ok(())
}

/// At most this many readings are named under a list that is not whole.
const GAPS_SHOWN: usize = 3;
/// The same for the list of servers.
const NONE_KNOWN: &str = "None known.";
/// The same for lists of devices seen in the private network.
const NONE_SEEN: &str = "None seen.";

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

/// What the owner's other devices are, on the summary and on the page beyond this Mac.
const YOUR_DEVICES: &str = "Phones, tablets and computers on your private network that you do not log in to over SSH. They are not checked: this version looks at this Mac and at servers.";

/// Servers, the owner's other devices, other people's devices and machines the owner set
/// aside, each in a section of its own.
pub fn beyond(conn: &Connection, latest: &[Latest], now: i64) -> Result<String, Box<dyn Error>> {
    // When its "none" was established: the last full check, as on the page of this Mac.
    let checked_at = crate::status::latest_check(conn)?.and_then(|r| r.finished_at);
    let mut out = top(
        "Beyond this Mac",
        &format!(
            "Last full check {} · this page made {}",
            utc_or(checked_at, "never"),
            utc(now)
        ),
    );
    let this = covered::this_machine(conn)?.unwrap_or_default();
    let split = beyond::split(conn, &this)?;
    // Every name and address each machine entity is known by.
    let mut names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT subject, object FROM assertion
         WHERE layer = 'live' AND predicate = 'known_as' AND subject LIKE 'machine:%'",
    )?;
    for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (subject, name) = row?;
        names.entry(subject).or_default().insert(name);
    }
    let visits: Vec<&Latest> = latest
        .iter()
        .filter(|r| r.reader == servers::READER && r.kind == servers::VISIT)
        .collect();
    let bare = |m: &str| m.strip_prefix("machine:").unwrap_or(m).to_string();
    // The name a machine is shown by, the one it was checked under if any, and the others.
    let named = |group: &[String]| -> (String, String) {
        let label = group
            .iter()
            .find(|m| visits.iter().any(|v| &v.scope == *m))
            .or(group.first())
            .map(|m| bare(m))
            .unwrap_or_default();
        let mut others: BTreeSet<String> = group.iter().map(|m| bare(m)).collect();
        for m in group {
            others.extend(names.get(m).into_iter().flatten().cloned());
        }
        others.remove(&label);
        (label, others.into_iter().collect::<Vec<_>>().join(", "))
    };

    // What each list rests on: the readings of this Mac that name machines.
    let latest_run = crate::status::latest_finished(conn)?.map(|r| r.started_at);
    let of_readers = |readers: &[&str]| -> Vec<&Latest> {
        latest
            .iter()
            .filter(|r| r.scope == this && readers.contains(&r.reader.as_str()))
            .collect()
    };
    let tailnet = unread(&of_readers(&[crate::tailnet::READER]), latest_run, now, &[]);

    out.push_str("<section id=\"servers\">\n<h2>Servers</h2>\n<p class=\"muted\">Machines you log in to over SSH, as your SSH settings, the list of machines SSH has connected to and the server check name them, and those your private network shows as yours. They are checked only when you run the server check; this program never connects to them by itself.</p>\n");
    let gap = unread(
        &of_readers(&[
            crate::ssh_config::READER,
            crate::known_hosts::READER,
            crate::tailnet::READER,
        ]),
        latest_run,
        now,
        &[],
    );
    coverage_of_list(
        &mut out,
        gap.as_deref(),
        split.servers.is_empty(),
        NONE_KNOWN,
    );
    if !split.servers.is_empty() {
        let mut rows: Vec<[String; 4]> = Vec::new();
        for group in &split.servers {
            let (label, others) = named(group);
            let mine: Vec<&&Latest> = visits.iter().filter(|v| group.contains(&v.scope)).collect();
            let state = match mine.iter().max_by_key(|v| v.at) {
                None => "not part of it".to_string(),
                Some(v) if v.completeness == "full" => "checked".to_string(),
                Some(v) if v.reason.as_deref() == Some(servers::NOT_COMPLETE) => {
                    "did not finish".to_string()
                }
                Some(v) => format!(
                    "could not be opened: {}",
                    view::said(v.reason.as_deref().unwrap_or_default())
                ),
            };
            let last = mine.iter().filter_map(|v| v.last_full).max();
            rows.push([label, state, utc_or(last, "never"), others]);
        }
        rows.sort();
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(
            &mut out,
            &[
                "Server",
                "At the last server check",
                "Last checked",
                "Also known as",
            ],
        );
        for [label, state, last, others] in rows {
            out.push_str("<tr>");
            view::td(&mut out, "mono", &label)?;
            view::td_said(&mut out, "", &state)?;
            view::td(&mut out, "nowrap", &last)?;
            view::td(&mut out, "mono", &others)?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    // Never guessed: a server the private network alone knows, without a system, says so.
    match split.system_not_given {
        0 => {}
        1 => out.push_str("<p class=\"muted\">1 of them is known only from your private network, which does not say what system it runs, so it is counted as a server.</p>\n"),
        n => writeln!(
            out,
            "<p class=\"muted\">{n} of them are known only from your private network, which does not say what system they run, so they are counted as servers.</p>"
        )?,
    }
    out.push_str("</section>\n");

    writeln!(
        out,
        "<section id=\"your-devices\">\n<h2>Your other devices</h2>\n<p class=\"muted\">{YOUR_DEVICES}</p>"
    )?;
    coverage_of_list(
        &mut out,
        tailnet.as_deref(),
        split.own_devices.is_empty(),
        NONE_SEEN,
    );
    if !split.own_devices.is_empty() {
        let mut rows: Vec<(String, String, String)> = split
            .own_devices
            .iter()
            .map(|g| {
                let (label, others) = named(g);
                let system = g
                    .iter()
                    .find_map(|m| split.platform.get(m))
                    .cloned()
                    .unwrap_or_default();
                (label, system, others)
            })
            .collect();
        rows.sort();
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(&mut out, &["Device", "System", "Also known as"]);
        for (label, system, others) in rows {
            out.push_str("<tr>");
            view::td(&mut out, "mono", &label)?;
            view::td(&mut out, "", &system)?;
            view::td(&mut out, "mono", &others)?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");

    out.push_str("<section id=\"other-devices\">\n<h2>Other devices</h2>\n<p class=\"muted\">Other people's computers and phones seen in your private network, such as a colleague's laptop. They are not yours to check, and this program does not read them. Only a Tailscale network is looked at; devices in a network of another kind are not known here.</p>\n");
    coverage_of_list(
        &mut out,
        tailnet.as_deref(),
        split.other_devices.is_empty(),
        NONE_SEEN,
    );
    if !split.other_devices.is_empty() {
        let mut rows: Vec<(String, String)> =
            split.other_devices.iter().map(|g| named(g)).collect();
        rows.sort();
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(&mut out, &["Device", "Also known as"]);
        for (label, others) in rows {
            out.push_str("<tr>");
            view::td(&mut out, "mono", &label)?;
            view::td(&mut out, "mono", &others)?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");

    out.push_str("<section id=\"retired\">\n<h2>Retired or not yours</h2>\n<p class=\"muted\">Machines you said are retired or not yours. They are not checked, and what was read on them before is kept.</p>\n");
    let standing: Vec<crate::owner::Standing> = crate::owner::standing(conn)?
        .into_iter()
        .filter(|s| s.seen.is_none())
        .collect();
    if standing.is_empty() {
        out.push_str("<p class=\"muted\">None.</p>\n");
    } else {
        out.push_str("<div class=\"scroll\"><table class=\"dense\">\n");
        view::thead(
            &mut out,
            &["Machine", "You said", "Since", "Why", "How it was given"],
        );
        for s in &standing {
            out.push_str("<tr>");
            view::td(&mut out, "mono", s.name())?;
            view::td(&mut out, "", &s.word.said)?;
            view::td(&mut out, "nowrap", &utc(s.word.made_at))?;
            view::td_said(&mut out, "", &s.word.reason.said())?;
            view::td(&mut out, "", view::given_by(s.word.via))?;
            out.push_str("</tr>\n");
        }
        out.push_str("</tbody></table></div>\n");
    }
    out.push_str("</section>\n");
    out.push_str(FOOT);
    Ok(out)
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
        "<li><a href=\"{BEYOND}.html\">Beyond this Mac: servers, your other devices, other people's devices, and machines you set aside</a></li>\n"
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

    /// The part of a page from the section with `id` to its end, or nothing.
    fn section_of<'a>(html: &'a str, id: &str) -> &'a str {
        let rest = html
            .find(&format!("<section id=\"{id}\">"))
            .map_or("", |i| &html[i..]);
        &rest[..rest.find("</section>").unwrap_or(rest.len())]
    }

    /// Nothing is hidden and nothing is told twice: every thing not covered, for every cause of
    /// the catalogue, is on the pages once, a fault in its own section and a limit in the
    /// collapsed section at the end, by the status's `fault` alone; a limit's names are there
    /// only, and stay text.
    #[test]
    fn every_thing_not_covered_is_on_the_pages_once_a_fault_in_its_section_a_limit_at_the_end() {
        let dir = crate::common::Scratch::new("pages-once");
        let conn = crate::store::open_or_make(&dir.join("store.db")).unwrap();
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
            let pages = view::pages(&conn, &r, &view::Answers::none(), "store.db", now).unwrap();
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
    }

    /// The state and the last read of the row of what is watched whose kind is `what`.
    fn row(r: &v1::Status, what: &str, now: i64) -> (String, String) {
        let faults: Vec<&v1::Uncovered> = r.not_covered.iter().filter(|u| u.fault).collect();
        let mut out = String::new();
        watched_table(&mut out, r, &faults, now).unwrap();
        let row = out
            .lines()
            .find(|l| l.contains(what))
            .unwrap_or_else(|| panic!("{what}: {out}"));
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
    /// to where it is told, by who can fix it. A row with no reading is "not checked yet".
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
                "<span class=\"dot off look\"></span><a href=\"{DETAILS}/{THIS_MAC}.html#{NOT_READ}\" aria-label=\"{NOT_READ_TITLE}: 2 can&#39;t be read now\">2 can&#39;t be read now</a>"
            )
        );
        assert!(
            with(fault(YOU, &[crate::watched::PROFILE])).contains("href=\"#you-can-fix\""),
            "{}",
            with(fault(YOU, &[crate::watched::PROFILE]))
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
}
