//! The text for a person of `immunity status`, `immunity status --coverage` and `immunity findings`,
//! rendered from the message alone for a screen (`screen.rs`). The default status says a state
//! and its faults, and nothing else: the answer in one line, then what needs a look by rule, each
//! with the command that shows it, then how this Mac is watched, then one line marked `!` for each
//! thing that should work on this Mac and does not now, with the command that ends it at the end
//! of its line. What this version does not read here, the counts of what was read and the detail
//! are in `--coverage` and in the machine forms. On a terminal no line is longer than the width;
//! in a pipe nothing is cut, no style is written and times are exact.
//!
//! Text from a source is in a message's `_text` fields, already escaped one to one
//! (`known::whole`), and every piece of text is escaped again as it reaches the screen, before
//! it is measured, cut or styled (`screen.rs`). In a column or beside a label it is data by its
//! place and goes without quotes (`Name::bare`); inside a sentence or a list it keeps them, each
//! name by itself (`Name::quoted`).
//!
//! Nothing a status says is calmer than the message: a fault the message holds (a check that
//! died, a watcher that does not watch live, an event level that records nothing or lost part of
//! it, a cause of class `failed`, a failed download) is always a line of the default status,
//! never dim.

use crate::contract::v1;
use crate::findings::SHORT_MAX;
use crate::screen::{
    self, BOLD, CYAN, Cell, Column, Cut, DIM, GREEN, PLAIN, RED, Screen, Style, YELLOW,
};
use crate::secrets::{Name, Said};
use crate::text::word;
use crate::view;

/// At most this many findings are listed in the text of `immunity findings`; the total is always
/// given.
const FINDINGS_SHOWN: usize = 200;

/// `n one` or `n many`, with thousands grouped.
pub(crate) fn count(n: u64, one: &str, many: &str) -> String {
    crate::things(i64::try_from(n).unwrap_or(i64::MAX), one, many)
}

/// `n` with thousands grouped.
pub(crate) fn grouped(n: u64) -> String {
    count(n, "", "").trim_end().to_string()
}

/// A text without the period that ends it, for a cell or a value beside a label.
pub(crate) fn unstopped(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// An enum's value in words: the JSON's name with spaces for underscores.
pub(crate) fn words<E: TryFrom<i32> + serde::Serialize>(value: i32) -> String {
    word::<E>(value).replace('_', " ")
}

/// The lines of a text, each ended.
pub(crate) fn joined(lines: &[String]) -> String {
    let mut out = String::new();
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// How bad, in the order of `findings::order`: a severity that is absent or that this build
/// does not know first, as the most severe.
pub(crate) fn rank(severity: Option<i32>) -> u8 {
    match severity.and_then(|s| v1::Level::try_from(s).ok()) {
        Some(v1::Level::Critical) => 5,
        Some(v1::Level::High) => 4,
        Some(v1::Level::Medium) => 3,
        Some(v1::Level::Low) => 2,
        Some(v1::Level::Informational) => 1,
        _ => 6,
    }
}

/// A level as a person reads it, and its style: critical red, high yellow, the others plain.
pub(crate) fn level(severity: Option<i32>) -> (String, Style) {
    match severity.map(|s| (s, v1::Level::try_from(s))) {
        None => ("not known".to_string(), PLAIN),
        Some((_, Ok(v1::Level::Critical))) => ("critical".to_string(), RED),
        Some((_, Ok(v1::Level::High))) => ("high".to_string(), YELLOW),
        Some((s, _)) => (words::<v1::Level>(s), PLAIN),
    }
}

/// A rule's name in a list: a published rule's own title, cut on a terminal to the length of a
/// short title, or the core's short title; the long title from a core that gives no short one.
pub(crate) fn short_title(
    screen: &Screen,
    rule_title: Option<&str>,
    short: &str,
    title: &str,
) -> String {
    match rule_title {
        Some(t) if screen.terminal => screen::cut_end(&Name::given(t).bare(), SHORT_MAX),
        Some(t) => Name::given(t).bare(),
        None if short.is_empty() => unstopped(title).to_string(),
        None => short.to_string(),
    }
}

/// The urgent ones of a count, in a cell: `urgent` when all are, how many when some are.
pub(crate) fn urgent_cell(count: u64, urgent: u64) -> String {
    match urgent {
        0 => String::new(),
        u if u >= count => "urgent".to_string(),
        u => format!("{} urgent", grouped(u)),
    }
}

/// How many need a look, never without how many of them are urgent.
pub(crate) fn needing(total: u64, urgent: u64) -> String {
    let (needs, need) = ("thing needs a look", "things need a look");
    format!(
        "{}, {}",
        count(total, needs, need),
        match urgent {
            0 => "none urgent".to_string(),
            u => format!("{} urgent", grouped(u)),
        }
    )
}

/// A machine as a person names it: an entity id's type and machine prefix left out.
fn machine_name(scope: &str) -> &str {
    for prefix in [
        "checkout:machine:",
        "container:machine:",
        "file:machine:",
        "machine:",
    ] {
        if let Some(rest) = scope.strip_prefix(prefix) {
            return rest;
        }
    }
    scope
}

/// The things a cause of what is not covered is about, each with what its source said. The cell
/// joins several texts from sources, so each keeps its own quotation, as today: a name that holds
/// a colon, a semicolon or a quote is never read as a name and a reason, or as two names.
fn examples(u: &v1::Uncovered) -> String {
    u.examples_text
        .iter()
        .enumerate()
        .map(
            |(i, name)| match u.examples.get(i).and_then(|e| e.reason_text.as_deref()) {
                Some(r) => format!(
                    "{}: {}",
                    Name::given(name).quoted(),
                    Said::given(r).quoted()
                ),
                None => Name::given(name).quoted(),
            },
        )
        .chain(u.value_text.as_deref().map(|v| Said::given(v).quoted()))
        .collect::<Vec<_>>()
        .join("; ")
}

/// A section of causes for `--coverage`: its label bold on a line when it has one, then each
/// cause's title and the things it is about, whole, both broken into lines. A fault is red
/// wherever it is listed.
fn cause_section(screen: &Screen, out: &mut Vec<String>, label: &str, list: &[&v1::Uncovered]) {
    if list.is_empty() {
        return;
    }
    let style = |u: &v1::Uncovered| {
        if u.fault { RED } else { PLAIN }
    };
    if !label.is_empty() {
        out.push(format!("  {}", screen.paint(BOLD, label)));
    }
    let room = screen.fits().map(|w| w.saturating_sub(6));
    for u in list {
        for l in screen::wrap(
            &view::shown(unstopped(&u.title)),
            screen.fits().map(|w| w.saturating_sub(4)),
        ) {
            out.push(format!("    {}", screen.paint(style(u), &l)));
        }
        let about = view::shown(&examples(u));
        if about.is_empty() {
            continue;
        }
        // Broken where it is too long and never cut; the lines a break makes are set in further,
        // so they never pass for a piece of their own.
        for (i, l) in screen::wrap(&about, room.map(|r| r.saturating_sub(2)))
            .iter()
            .enumerate()
        {
            let indent = if i == 0 { "      " } else { "        " };
            out.push(format!("{indent}{}", screen.paint(PLAIN, l)));
        }
    }
}

/// The state of this Mac and of its watcher, in words, with the style it is shown in: a watcher
/// that failed red, watched in part or not checked yellow.
pub(crate) fn watching(s: &v1::Status, screen: &Screen) -> (String, Style) {
    let Some(m) = &s.this_mac else {
        return ("whether it is watched is not said".to_string(), YELLOW);
    };
    let state = match v1::ThisMacState::try_from(m.state) {
        Ok(v1::ThisMacState::Watched) => "yes",
        Ok(v1::ThisMacState::WatchedInPart) => "in part",
        _ => "not checked yet",
    };
    let failed: Vec<&str> = s
        .watching
        .as_ref()
        .map(|w| {
            w.failed
                .iter()
                .map(|f| crate::watch::failed_words(&f.what))
                .collect()
        })
        .unwrap_or_default();
    let style = if !failed.is_empty() {
        RED
    } else if state == "yes" && m.live {
        PLAIN
    } else {
        YELLOW
    };
    use crate::watch::Case;
    let watcher = match crate::watch::case(s) {
        Case::Live => "live".to_string(),
        Case::LiveFailed => format!("live, with a failed {}", failed.join(" and ")),
        Case::Failing => crate::watch::failing_words(&failed),
        Case::Starting => crate::watch::STARTING_WORDS.to_string(),
        Case::Restarting => crate::watch::RESTARTING_WORDS.to_string(),
        Case::OffNotByCommand { on, job } => format!(
            "Immunity Core is off, and immunity off did not turn it off. It was turned on {}{}. Turn it on with: immunity on",
            screen.time(on, s.answered_at),
            match job {
                Some(true) => "; its job is in place and not running",
                Some(false) => "; its job is gone",
                None => "",
            }
        ),
        Case::OffByCommand { off } => format!(
            "Immunity Core is off: turned off {} with immunity off",
            screen.time(off, s.answered_at)
        ),
        // Read from the property list alone: whether launchd has the job is not asked.
        Case::JobInPlace => "installed, not running: the login job is in place and no watcher runs now, so changes are seen at each check".to_string(),
        Case::NotInstalled => {
            "not installed: no watcher runs now, so changes are seen at each check".to_string()
        }
        Case::NoWatcher => "no watcher runs now: changes are seen at each check".to_string(),
    };
    (format!("{state}; {watcher}"), style)
}

/// The downloads of public threat data that failed at the last check, in two sentences: those
/// whose data read before stays in force, and those of which nothing is known yet; none when none
/// failed. Said even while the headline stays calm because the data kept is current. What a
/// cause of `not_covered` already says is left out: the catalogue (`catalogue_said`), and a feed
/// that answers rest on and that was never read (`data_said`), which is not current. An outcome
/// this build does not know is read as failed, as the schema says.
fn downloads_failed(s: &v1::Status, catalogue_said: bool, data_said: bool) -> Vec<String> {
    let failed = |outcome: i32| {
        !matches!(
            v1::FeedOutcome::try_from(outcome),
            Ok(v1::FeedOutcome::Read | v1::FeedOutcome::Unchanged | v1::FeedOutcome::NeverRead)
        )
    };
    // What failed, in two groups: the catalogue, and the ecosystems of the OSV data.
    let mut kept = (false, Vec::new());
    let mut none = (false, Vec::new());
    if let Some(t) = s
        .threats
        .as_ref()
        .filter(|t| failed(t.outcome) && !catalogue_said)
    {
        let group = if t.entries.is_some() || t.read_at.is_some() {
            &mut kept
        } else {
            &mut none
        };
        group.0 = true;
    }
    for f in s
        .vulnerability_data
        .iter()
        .flat_map(|d| &d.feeds)
        .filter(|f| failed(f.outcome) && !(data_said && f.matched && f.read_at.is_none()))
    {
        let group = if f.read_at.is_some() {
            &mut kept
        } else {
            &mut none
        };
        group.1.push(f.ecosystem.as_str());
    }
    let named = |(catalogue, ecosystems): &(bool, Vec<&str>)| {
        let mut names = Vec::new();
        if *catalogue {
            names.push("CISA catalogue".to_string());
        }
        if !ecosystems.is_empty() {
            names.push(format!("OSV data for {}", ecosystems.join(", ")));
        }
        names.join(" and ")
    };
    let mut said = Vec::new();
    if kept.0 || !kept.1.is_empty() {
        said.push(format!(
            "{} not downloaded at the last check, the data read before stays in force",
            named(&kept)
        ));
    }
    if none.0 || !none.1.is_empty() {
        said.push(format!(
            "{} not downloaded, nothing of it is known yet",
            named(&none)
        ));
    }
    said
}

/// The causes of `not_covered` the event level's own line says when none of them is there.
const EVENT_CAUSES: [&str; 3] = [
    crate::covered::EVENTS_REFUSED.id,
    crate::covered::EVENTS_FAILING.id,
    crate::covered::EVENTS_SILENT.id,
];
/// The causes of `not_covered` that say a failed download of the catalogue, which the line of
/// downloads then leaves out.
const CATALOGUE_CAUSES: [&str; 2] = [
    crate::covered::THREATS_UNREAD.id,
    crate::covered::THREATS_FIXABLE.id,
];
/// The causes of `not_covered` that say the vulnerability data answers rest on is not current.
const DATA_CAUSES: [&str; 2] = [
    crate::covered::VULNERABILITY_DATA_OLD.id,
    crate::covered::VULNERABILITY_DATA_FIXABLE.id,
];

/// Something that should work on this Mac and does not now, as one line of the default status,
/// marked `!`: the core's words, what a source said of it, the core's words after that, and the
/// command that ends it, with what the person can do on a line of its own under it.
pub(crate) struct Fault {
    words: String,
    /// What a source said, as printed (`Said::quoted`), cut on a terminal to a line: a sentence
    /// keeps its start, names their start and end. Whole in a pipe.
    said: Option<(String, Cut)>,
    tail: String,
    command: Option<&'static str>,
    advice: Option<String>,
    /// That no watcher watches live, without a failure of one: what a status that is not fresh
    /// gives as its reason.
    not_live: bool,
}

impl Fault {
    fn new(words: impl Into<String>) -> Fault {
        Fault {
            words: words.into(),
            said: None,
            tail: String::new(),
            command: None,
            advice: None,
            not_live: false,
        }
    }

    fn said(mut self, text: Option<&str>, cut: Cut) -> Fault {
        self.said = text.filter(|t| !t.is_empty()).map(|t| (t.to_string(), cut));
        self
    }

    fn run(mut self, command: &'static str) -> Fault {
        self.command = Some(command);
        self
    }

    /// Its words, what the source said, the words after that, its command and its advice, whole.
    pub(crate) fn parts(&self) -> (&str, Option<&str>, &str, Option<&'static str>, Option<&str>) {
        let said = self.said.as_ref().map(|(t, _)| t.as_str());
        (
            &self.words,
            said,
            &self.tail,
            self.command,
            self.advice.as_deref(),
        )
    }
}

/// A sentence of the core's own with its first letter a capital.
fn sentence(s: &str) -> String {
    let mut chars = s.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// How often, in words: once, twice, or a count of times.
fn times(n: u64) -> String {
    match n {
        1 => "once".to_string(),
        2 => "twice".to_string(),
        n => count(n, "time", "times"),
    }
}

/// Every fault the message holds, in the order a person acts on them: a check that died, the
/// watcher, the event level, every cause with `fault` (only `with_causes`, as `--coverage` lists
/// them whole on their own), the downloads that failed. A limit of this version is none of them.
fn faults(s: &v1::Status, screen: &Screen, with_causes: bool) -> Vec<Fault> {
    let now = s.answered_at;
    let mut out = Vec::new();
    // The core says `running` only of the latest start, by that run's own lock.
    if let Some(l) = s
        .last_run
        .as_ref()
        .filter(|l| l.finished_at.is_none() && !s.running)
    {
        out.push(
            Fault::new(format!(
                "The check started {} did not finish",
                screen.time(l.started_at, now)
            ))
            .run("immunity run"),
        );
    }
    out.extend(watcher_faults(s, screen));
    let failed: Vec<&v1::Uncovered> = s.not_covered.iter().filter(|u| u.fault).collect();
    let any = |ids: &[&str]| failed.iter().any(|u| ids.contains(&u.id.as_str()));
    if let Some(l) = &s.event_level {
        out.extend(event_faults(l, any(&EVENT_CAUSES)));
    }
    if with_causes {
        out.extend(failed.iter().map(|u| cause_fault(u)));
    }
    out.extend(
        downloads_failed(s, any(&CATALOGUE_CAUSES), any(&DATA_CAUSES))
            .into_iter()
            .map(Fault::new),
    );
    out
}

/// The watcher when it does not watch live: each failure that stands, with when and what it
/// said; or, with none, why no watcher watches live and the command that starts one. None while
/// a watcher watches live, as the headline's rule has it: `this_mac.live`, a watcher on the store
/// and no failure.
fn watcher_faults(s: &v1::Status, screen: &Screen) -> Vec<Fault> {
    let now = s.answered_at;
    let out: Vec<Fault> = s
        .watching
        .iter()
        .flat_map(|w| &w.failed)
        .map(|f| {
            let fault = Fault::new(format!(
                "The watcher's latest {} failed {}",
                crate::watch::failed_words(&f.what),
                screen.time(f.at, now)
            ))
            .said(Some(&Said::given(&f.detail_text).quoted()), Cut::End);
            match f.what == crate::watch::FULL_CHECK {
                true => fault.run("immunity run"),
                false => fault,
            }
        })
        .collect();
    // Every sentence of the watcher is its case's (`watch::case`), as on the pages.
    use crate::watch::Case;
    let fault = match crate::watch::case(s) {
        // Each failure that stands is said above.
        Case::Live | Case::LiveFailed | Case::Failing => return out,
        Case::Restarting => Fault::new(sentence(crate::watch::RESTARTING_WORDS)),
        Case::Starting => Fault::new(sentence(crate::watch::STARTING_WORDS)),
        Case::OffNotByCommand { on, job } => Fault::new(match job {
            Some(false) => format!(
                "Immunity Core is off: its job, turned on {}, is gone, and immunity off did not turn it off",
                screen.time(on, now)
            ),
            Some(true) => format!(
                "Immunity Core is off: its job, turned on {}, is in place and not running, and immunity off did not turn it off",
                screen.time(on, now)
            ),
            None => format!(
                "Immunity Core is off: turned on {}, and immunity off did not turn it off",
                screen.time(on, now)
            ),
        })
        .run("immunity on"),
        Case::OffByCommand { off } => Fault::new(format!(
            "Immunity Core is off: turned off {} with immunity off",
            screen.time(off, now)
        ))
        .run("immunity on"),
        // Read from the property list alone: whether launchd has the job is not asked.
        Case::JobInPlace => {
            Fault::new("The watcher is not running: its login job is in place").run("immunity on")
        }
        Case::NotInstalled | Case::NoWatcher => {
            Fault::new("No watcher runs: changes are seen only at a check you run").run("immunity on")
        }
    };
    vec![Fault {
        not_live: true,
        ..fault
    }]
}

/// The event level when it is installed and records nothing, unless a cause of `not_covered`
/// says so (`said_by_cause`); or, while it records, what it lost since the latest full check, by
/// the counts the message gives. Not installed is a limit and says nothing.
fn event_faults(l: &v1::EventLevel, said_by_cause: bool) -> Vec<Fault> {
    use v1::CollectorState as C;
    match C::try_from(l.state) {
        Ok(C::NotInstalled) => return Vec::new(),
        Ok(C::Running) => {}
        _ if said_by_cause => return Vec::new(),
        _ => {
            let state = l.in_words.as_ref().map_or("", |w| w.state.as_str());
            let state = if state.is_empty() {
                "not running"
            } else {
                state
            };
            let said = (l.said_text.as_deref().or(l.reason_text.as_deref()))
                .map(|t| Said::given(t).quoted());
            return vec![
                Fault::new(format!("Program starts are not seen; event level: {state}"))
                    .said(said.as_deref(), Cut::End),
            ];
        }
    }
    // Each loss since the latest full check, which a check that finishes reads past.
    let since = |s: &Option<v1::Span>| s.as_ref().map_or(0, |s| s.since_check);
    let file_events = l.file_events.as_ref().filter(|f| f.collected);
    let unreadable = l.unreadable_lines.unwrap_or_default();
    let counted =
        |n: u64, one: &str, many: &str| format!("{} since the latest check", count(n, one, many));
    let restarted = |n: u64, what: &str, after: &str| {
        format!("{what} {} since the latest check{after}", times(n))
    };
    let losses = [
        (
            since(&l.lost),
            counted(
                since(&l.lost),
                "program start was missed",
                "program starts were missed",
            ),
        ),
        (
            since(&l.unknown_losses),
            restarted(
                since(&l.unknown_losses),
                "The collector restarted",
                ", and program starts in those moments were not seen",
            ),
        ),
        (
            unreadable.since_check,
            counted(
                unreadable.since_check,
                "line of the event log could not be read",
                "lines of the event log could not be read",
            ),
        ),
        (
            since(&l.files_removed_unread),
            counted(
                since(&l.files_removed_unread),
                "file of the event log was deleted before it was read",
                "files of the event log were deleted before they were read",
            ),
        ),
        (
            file_events.map_or(0, |f| since(&f.lost) + since(&f.unreadable_events)),
            counted(
                file_events.map_or(0, |f| since(&f.lost) + since(&f.unreadable_events)),
                "file event was missed",
                "file events were missed",
            ),
        ),
        (
            file_events.map_or(0, |f| since(&f.unknown_losses)),
            restarted(
                file_events.map_or(0, |f| since(&f.unknown_losses)),
                "The numbering of file events started again",
                "",
            ),
        ),
    ];
    losses
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(_, said)| Fault::new(said).run("immunity run"))
        .collect()
}

/// A cause that is a fault, as a line: what could not be read, by name, for one of this Mac or
/// the projects that names its things; any other by its title and what its source said. What the
/// person can do follows when the person can change it.
fn cause_fault(u: &v1::Uncovered) -> Fault {
    // Each name with what its source said of it, where it said something; names alone
    // otherwise. A place of this Mac or a project is said as a place that could not be read;
    // anything else by its title, with its names where they come with a reason.
    let reason = |i: usize| u.examples.get(i).and_then(|e| e.reason_text.as_deref());
    let with_reasons = (0..u.examples_text.len()).any(|i| reason(i).is_some());
    let place = ["this_mac", "projects"].contains(&u.scope.as_str());
    let mut fault = if u.examples_text.is_empty() {
        let value = u.value_text.as_deref().map(|v| Said::given(v).quoted());
        Fault::new(unstopped(&u.title)).said(value.as_deref(), Cut::End)
    } else {
        let names: Vec<String> = u
            .examples_text
            .iter()
            .enumerate()
            .map(|(i, n)| match reason(i) {
                Some(r) => format!("{}: {}", Name::given(n).quoted(), Said::given(r).quoted()),
                None => Name::given(n).quoted(),
            })
            .collect();
        // A place by its names alone; anything else by its title, and its names with what the
        // source said of the whole, as the full account gives them, where none has a reason.
        let read = match u.id == crate::fault::NO_LONGER_READ.id {
            true => "Can no longer be read",
            false => "Could not read",
        };
        let (words, names) = match (place, with_reasons) {
            (true, _) => (read, names.join(if with_reasons { "; " } else { ", " })),
            (false, true) => (unstopped(&u.title), names.join("; ")),
            (false, false) => (unstopped(&u.title), examples(u)),
        };
        let mut fault = Fault::new(words).said(Some(&names), Cut::Middle);
        let more = u.count.saturating_sub(u.examples_text.len() as u64);
        if more > 0 {
            fault.tail = format!(", and {} more", grouped(more));
        }
        fault
    };
    fault.advice = (u.who == "you" && !u.advice.is_empty()).then(|| u.advice.clone());
    fault
}

/// A line under the headline, set in by `indent`: `mark` and a space before it when one is given,
/// then `lines`, each painted and with the columns it takes, the lines after the first set in
/// under the start of the first; and `command` cyan at the right edge of the last, or on a line
/// of its own set to the right where they do not fit side by side. In a pipe the command follows
/// the last line.
fn aside(
    screen: &Screen,
    indent: usize,
    mark: Option<(&str, Style)>,
    lines: &[(String, usize)],
    command: Option<&str>,
) -> Vec<String> {
    let lead = indent + mark.map_or(0, |(m, _)| screen::columns(m) + 1);
    let mut out: Vec<String> = lines
        .iter()
        .enumerate()
        .map(|(i, (l, _))| match (i, mark) {
            (0, Some((m, st))) => format!("{}{} {l}", " ".repeat(indent), screen.paint(st, m)),
            _ => format!("{}{l}", " ".repeat(lead)),
        })
        .collect();
    let Some(c) = command else { return out };
    let painted = screen.paint(CYAN, c);
    let last = lead + lines.last().map_or(0, |(_, n)| *n);
    let wide = screen::columns(c);
    match (screen.fits(), out.last_mut()) {
        (Some(width), Some(line)) if last + 3 + wide <= width => {
            line.push_str(&" ".repeat(width - last - wide));
            line.push_str(&painted);
        }
        (Some(width), _) => out.push(format!(
            "{}{painted}",
            " ".repeat(width.saturating_sub(wide))
        )),
        (None, Some(line)) => line.push_str(&format!("   {painted}")),
        (None, None) => out.push(painted),
    }
    out
}

/// A text already escaped, broken into lines that fit after `lead` columns on a terminal and one
/// line in a pipe, each painted in `style`, with the columns it takes.
fn painted(screen: &Screen, lead: usize, text: &str, style: Style) -> Vec<(String, usize)> {
    screen::wrap(text, screen.fits().map(|w| w.saturating_sub(lead).max(1)))
        .into_iter()
        .map(|l| (screen.paint(style, &l), screen::columns(&l)))
        .collect()
}

/// A fault's lines: `!` yellow, the words, what the source said and the command; then what the
/// person can do, set in under the words. On a terminal what the source said follows the words
/// on their line when it fits there whole, and otherwise has a line of its own, cut to it.
fn fault_lines(screen: &Screen, indent: usize, f: &Fault) -> Vec<String> {
    let lead = indent + 2;
    let room = screen.fits().map(|w| w.saturating_sub(lead).max(1));
    let tail = view::shown(&f.tail);
    let mut text = view::shown(&f.words);
    let mut own_line = None;
    if let Some((said, cut)) = &f.said {
        let said = view::shown(said);
        text.push(':');
        let last = screen::wrap(&text, room)
            .last()
            .map_or(0, |l| screen::columns(l));
        match room {
            Some(r) if last + 1 + screen::columns(&said) + screen::columns(&tail) > r => {
                let r = r.saturating_sub(screen::columns(&tail)).max(1);
                own_line = Some(match cut {
                    Cut::Middle => screen::cut_middle(&said, r),
                    _ => screen::cut_end(&said, r),
                });
            }
            _ => text.push_str(&format!(" {said}")),
        }
    }
    let mut lines = painted(screen, lead, &text, PLAIN);
    match own_line {
        Some(said) => lines.extend(painted(screen, lead, &format!("{said}{tail}"), PLAIN)),
        None if !tail.is_empty() => {
            text.push_str(&tail);
            lines = painted(screen, lead, &text, PLAIN);
        }
        None => {}
    }
    let mut out = aside(screen, indent, Some(("!", YELLOW)), &lines, f.command);
    if let Some(a) = &f.advice {
        for (l, _) in painted(screen, lead, &view::shown(a), PLAIN) {
            out.push(format!("{}{l}", " ".repeat(lead)));
        }
    }
    out
}

/// The full sentence of the event level, as `--coverage` gives it.
fn event_level_long(l: &v1::EventLevel) -> String {
    let words = l.in_words.clone().unwrap_or_default();
    let head = match (
        v1::CollectorState::try_from(l.state),
        l.program_starts.as_ref(),
    ) {
        (Ok(v1::CollectorState::Running), Some(p)) => format!(
            "{}, {} in the last day.",
            words.state,
            count(p.last_day, "program start", "program starts")
        ),
        _ => format!("{}.", words.state),
    };
    let line: Vec<String> = std::iter::once(head).chain(words.notes).collect();
    unstopped(&line.join(" ")).to_string()
}

/// `immunity status` for a person. With `coverage`, `immunity status --coverage`: everything the
/// last check read and did not read, laid out by the same rules.
pub fn status(s: &v1::Status, screen: &Screen, coverage: bool) -> String {
    let store = s.store.clone().unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    if !store.exists {
        out.extend(crate::text::no_store(screen));
        out.push(String::new());
        let path = Name::given(&store.path_text).bare();
        out.extend(screen.labelled(2, 5, "Store", &path, PLAIN, None, 0));
        out.push(String::new());
        out.push(screen.next("immunity run", "makes it"));
        return joined(&out);
    }
    if coverage {
        coverage_text(s, screen, &mut out);
    } else {
        out.extend(answer(s, screen, "", None, &[]));
    }
    joined(&out)
}

/// When the latest full check finished, for the right of a first line.
fn checked(screen: &Screen, s: &v1::Status) -> Option<String> {
    s.this_mac
        .as_ref()
        .and_then(|m| m.checked_at)
        .map(|at| format!("checked {}", screen.time(at, s.answered_at)))
}

/// What the default status says of a message, decided once for its text and for the pages:
/// the headline's words, style and what goes at its right; whether what needs a look is said;
/// the state under the headline, its words and command; and every fault, in order.
pub(crate) struct Told {
    said: String,
    style: Style,
    right: Option<String>,
    findings: bool,
    pub(crate) state: Option<(String, Option<&'static str>)>,
    pub(crate) faults: Vec<Fault>,
}

/// The decision `answer` lays out, from the message alone.
pub(crate) fn told(s: &v1::Status, screen: &Screen) -> Told {
    use v1::Headline as H;
    let now = s.answered_at;
    let mut faults = faults(s, screen, true);
    let look = s.needs_a_look.as_ref();
    let checking = |at: Option<String>| match (at, s.running) {
        (Some(at), true) => Some(format!("{at} · checking now")),
        (None, true) => Some("checking now".to_string()),
        (at, false) => at,
    };
    let headline = H::try_from(s.headline);
    let m = s.this_mac.as_ref();
    let fresh = m.is_some_and(|m| m.fresh);
    let finished = m.and_then(|m| m.checked_at).is_some();
    // A finding is a finding however the message counts it.
    let findings = headline == Ok(H::NeedsALook)
        || look.is_some_and(|n| n.total > 0 || !n.items.is_empty() || !n.by_rule.is_empty());
    // Off is the headline only when it hides neither a finding nor a check that runs; otherwise
    // its own fault line says it.
    let off = match crate::watch::case(s) {
        crate::watch::Case::OffByCommand { off } => Some(off),
        _ => None,
    }
    .filter(|_| !findings && !s.running);
    // An answer that is not fresh is said beside what was found, by the reason the message gives.
    if findings && !fresh {
        let no_watcher = !matches!(
            crate::watch::case(s),
            crate::watch::Case::Live
                | crate::watch::Case::LiveFailed
                | crate::watch::Case::Failing
                | crate::watch::Case::Starting
                | crate::watch::Case::Restarting
        );
        let reason = m.and_then(|m| m.stale_reason.as_deref());
        faults.insert(
            0,
            Fault::new("This answer is not fresh")
                .said(reason, Cut::End)
                .run(if no_watcher {
                    "immunity on"
                } else {
                    "immunity run"
                }),
        );
    }
    // The state under the headline: its words and command, or a fault taken to say it.
    let mut state: Option<(String, Option<&'static str>)> = None;
    let take_not_live = |faults: &mut Vec<Fault>| {
        faults.iter().position(|f| f.not_live).map(|i| {
            let f = faults.remove(i);
            (f.words, f.command)
        })
    };
    // One order of precedence, each form claiming only what the message shows: a finding; off;
    // the first check running; no run of this build that looked; no finished check; not fresh;
    // nothing to look at, by the headline; and what is not known.
    let (said, style, own_right) = if findings {
        let n = look.cloned().unwrap_or_default();
        let urgent = match n.urgent_total {
            0 => String::new(),
            u => format!(" · {} urgent", grouped(u)),
        };
        let style = if n.urgent_total > 0 { RED } else { YELLOW };
        // Never fewer than the message lists, by item or by rule.
        let total = n
            .total
            .max(n.items.len() as u64)
            .max(n.by_rule.iter().map(|g| g.count).sum());
        (
            format!(
                "● {}{urgent}",
                count(total, "thing needs a look", "things need a look")
            ),
            style.bold(),
            checking(checked(screen, s)),
        )
    } else if let Some(at) = off {
        take_not_live(&mut faults);
        state = Some((
            "Nothing is watched or checked until it is turned on".to_string(),
            Some("immunity on"),
        ));
        (
            "○ Immunity Core is off".to_string(),
            BOLD,
            Some(format!("turned off {}", screen.time(at, now))),
        )
    } else if s.running && !finished {
        state = stage(s, screen).map(|said| (sentence(&said), None));
        (
            "… The first check is running".to_string(),
            YELLOW.bold(),
            s.last_run
                .as_ref()
                .map(|l| format!("started {}", screen.time(l.started_at, now))),
        )
    } else if look.is_none() {
        state = Some(("Check this Mac now".to_string(), Some("immunity run")));
        (
            "? No run of this build has looked for findings yet".to_string(),
            YELLOW.bold(),
            None,
        )
    } else if !finished {
        state = Some(("Check this Mac now".to_string(), Some("immunity run")));
        (
            "? No check has finished yet".to_string(),
            YELLOW.bold(),
            None,
        )
    } else if !fresh {
        // No watcher is why no check ran; otherwise the core's own reason.
        let m = m.cloned().unwrap_or_default();
        state = take_not_live(&mut faults).or_else(|| {
            let why = m
                .stale_reason
                .as_deref()
                .unwrap_or("the core does not say why");
            Some((sentence(why), Some("immunity run")))
        });
        let since = m
            .checked_at
            .map_or_else(String::new, |at| format!(" {}", screen.since(at, now)));
        (
            format!("? Not checked{since}"),
            YELLOW.bold(),
            checking(None),
        )
    } else if matches!(headline, Ok(H::InPart | H::Calm)) {
        (
            "✓ Nothing needs a look".to_string(),
            GREEN.bold(),
            checking(checked(screen, s)),
        )
    } else {
        (
            "? Whether this Mac is watched is not known".to_string(),
            YELLOW.bold(),
            None,
        )
    };
    // In part never shows a bare ✓: a fault line says what was not read in full, or this one does
    // where none says it. A limit never holds it in part (`fault.rs`).
    if said.starts_with('✓') && headline == Ok(H::InPart) && faults.is_empty() {
        faults.push(Fault::new("Something was not read in full").run("immunity status --coverage"));
    }
    // A watcher watching live says so under a headline that says what was found.
    let live = matches!(
        crate::watch::case(s),
        crate::watch::Case::Live | crate::watch::Case::LiveFailed
    );
    let calm = said.starts_with('✓');
    if state.is_none() && live && (findings || calm) {
        let projects = s.estate.as_ref().map_or(0, |e| e.checkouts);
        let what = match projects {
            0 => "this Mac".to_string(),
            n => format!("this Mac and {}", count(n, "project", "projects")),
        };
        state = Some((format!("Watching live · {what}"), None));
    }
    Told {
        said,
        style,
        right: own_right,
        findings,
        state,
        faults,
    }
}

/// The default text of `immunity status` and the text of `immunity run`, from the message alone:
/// the headline in the words of the status's own `headline`, with `tail` after its words and
/// `right` at its right edge, or the status's own time there without one; what needs a look by
/// rule; the line that says the state, with its command; the lines the command adds of its own
/// (`own`); then every fault. A value of `headline` this build does not know is said as not
/// known, never as calm.
pub(crate) fn answer(
    s: &v1::Status,
    screen: &Screen,
    tail: &str,
    right: Option<String>,
    own: &[String],
) -> Vec<String> {
    let Told {
        said,
        style,
        right: own_right,
        findings,
        state,
        faults,
    } = told(s, screen);
    let look = s.needs_a_look.as_ref();
    let mut out = screen.headline(
        &format!("{said}{tail}"),
        style,
        right.or(own_right).as_deref(),
    );
    if findings && let Some(n) = look {
        out.extend(needing_lines(screen, n));
    }
    if let Some((words, command)) = &state {
        let lines = painted(screen, 2, &view::shown(words), PLAIN);
        out.extend(aside(screen, 2, None, &lines, *command));
    }
    for line in own {
        let lines = painted(screen, 2, &view::shown(line), PLAIN);
        out.extend(aside(screen, 2, None, &lines, None));
    }
    for f in &faults {
        out.extend(fault_lines(screen, 2, f));
    }
    out
}

/// What needs a look, by rule as the message orders them, each on two lines: its level and what
/// it is, then the command that shows it. A rule with one finding the message lists says what
/// that one is about and names it; a rule with more says how many, and how many of them are
/// urgent, and the command that lists them.
fn needing_lines(screen: &Screen, n: &v1::NeedsALook) -> Vec<String> {
    if n.by_rule.is_empty() {
        return vec![format!("  {}", screen.paint(CYAN, "immunity findings"))];
    }
    let mut rows: Vec<Vec<Cell>> = Vec::new();
    let mut under: Vec<(Vec<(String, Style)>, String)> = Vec::new();
    for g in &n.by_rule {
        let (lv, style) = level(g.severity);
        let title = short_title(
            screen,
            g.rule_title_text.as_deref(),
            &g.short_title,
            &g.rule,
        );
        let one = n
            .items
            .iter()
            .filter_map(|i| i.finding.as_ref())
            .find(|l| l.finding.as_ref().and_then(|r| r.rule.as_deref()) == Some(g.rule.as_str()))
            .filter(|_| g.count == 1);
        let urgent = urgent_cell(g.count, g.urgent);
        let mut next: Vec<(String, Style)> = Vec::new();
        let (cell, command) = match one {
            Some(l) => {
                let about = telling(l);
                let id = l.finding.as_ref().map_or("", |r| r.id.as_str());
                let command = format!("immunity finding {id}");
                if about.text.is_empty() {
                    (Cell::plain(title), command)
                } else {
                    // A published rule's own title is a name in this sentence.
                    let title = match g.rule_title_text.as_deref() {
                        Some(t) => Name::given(t).quoted(),
                        None => title,
                    };
                    let keep = screen::columns(&view::shown(&title)) + 2 + about.keep;
                    let cell = Cell::plain(format!("{title}: {}", about.text)).keeping(keep);
                    (cell, command)
                }
            }
            None => {
                next.push((count(g.count, "finding", "findings"), BOLD));
                (Cell::plain(title), "immunity findings".to_string())
            }
        };
        if !urgent.is_empty() {
            if !next.is_empty() {
                next.push((", ".to_string(), PLAIN));
            }
            next.push((urgent, RED));
        }
        rows.push(vec![Cell::new(lv, style), cell]);
        under.push((next, command));
    }
    let indent = 2
        + n.by_rule
            .iter()
            .map(|g| screen::columns(&level(g.severity).0))
            .max()
            .unwrap_or(0)
        + 2;
    let drawn = screen.table(
        2,
        &[Column::new(Cut::Never), Column::new(Cut::Middle)],
        None,
        &rows,
    );
    // Under each, how many and the command after them, or the command on a line of its own
    // where both do not fit.
    let mut out = Vec::new();
    for (line, (next, command)) in drawn.into_iter().zip(under) {
        out.push(line);
        let wide: usize = next.iter().map(|(t, _)| screen::columns(t)).sum();
        let mut said: String = next.iter().map(|(t, st)| screen.paint(*st, t)).collect();
        let fits = screen
            .fits()
            .is_none_or(|w| indent + wide + 3 + screen::columns(&command) <= w);
        let command = screen.paint(CYAN, &command);
        match (wide, fits) {
            (0, _) => said = command,
            (_, true) => said = format!("{said}   {command}"),
            (_, false) => {
                out.push(format!("{}{said}", " ".repeat(indent)));
                said = command;
            }
        }
        out.push(format!("{}{said}", " ".repeat(indent)));
    }
    out
}

/// The command that lists every application bundle with what macOS says of its seal.
const LISTS_SEALS: &str = "immunity machine --json";

/// How many application bundles do not verify, and how many of them have not since the first
/// check; `None` when all verify.
fn not_verifying(i: &v1::Integrity) -> Option<String> {
    let (n, first) = (i.bundles_not_verifying, i.not_verifying_since_first_reading);
    let since = match first {
        f if f >= n && n == 1 => String::new(),
        f if f >= n => "all ".to_string(),
        f => format!("{} of them ", grouped(f)),
    };
    (n > 0).then(|| {
        format!(
            "{}, {since}since the first check",
            count(n, "app does not verify", "apps do not verify")
        )
    })
}

/// Why what the status says is not fresh, for both texts; `None` when it is fresh. While a full
/// check runs and none has finished, that one is running and since when, never that there has
/// been none.
fn not_fresh(s: &v1::Status, screen: &Screen) -> Option<String> {
    let m = s.this_mac.as_ref().filter(|m| !m.fresh)?;
    // The core says `running` only of the latest start, by that run's own lock.
    let running = s.last_run.as_ref().filter(|_| s.running);
    let why = match (m.checked_at, running) {
        (None, Some(l)) => format!(
            "a full check is running, started {}, and none has finished yet",
            screen.time(l.started_at, s.answered_at)
        ),
        _ => m
            .stale_reason
            .as_deref()
            .unwrap_or("the core does not say why")
            .to_string(),
    };
    Some(format!(
        "{why}; do not take it for calm until a check finishes"
    ))
}

/// The line of a check that started and has not finished: it runs, with the stage it noted and
/// for how long, or it stopped: it died, or it met a store held past its wait and is asked again.
/// The stage is said only beside `running`, which alone says it runs.
fn unfinished(s: &v1::Status, screen: &Screen, started_at: i64) -> (String, Style) {
    let started = screen.time(started_at, s.answered_at);
    if !s.running {
        let said = format!(
            "started {started} and has not finished: it stopped, and nothing it read is in the store"
        );
        return (said, RED);
    }
    let stage = stage(s, screen).map_or_else(String::new, |said| format!(", {said}"));
    let said = format!("started {started} and has not finished: it is running{stage}");
    (said, YELLOW)
}

/// The stage the running check noted and for how long, such as "reading events for 3 min";
/// `None` for a stage this build cannot name or one without its time.
fn stage(s: &v1::Status, screen: &Screen) -> Option<String> {
    use v1::CheckStage as C;
    let words = match s.check_stage.and_then(|v| C::try_from(v).ok()) {
        Some(C::Downloading) => "downloading vulnerability data",
        Some(C::Packages) => "reading packages and servers",
        Some(C::Projects) => "looking for projects",
        Some(C::Lockfiles) => "reading lockfiles",
        Some(C::Places) => "reading what runs by itself",
        Some(C::Software) => "looking for software changed in place",
        Some(C::Events) => "reading events",
        Some(C::Saving) => "matching and saving",
        Some(C::Unspecified) | None => "",
    };
    let at = s.check_stage_started_at.filter(|_| !words.is_empty())?;
    Some(format!("{words} {}", screen.since(at, s.answered_at)))
}

/// What the latest check that finished counted, one labelled part each, in the words today's
/// status said them in one paragraph.
fn counted(screen: &Screen, s: &v1::Status, f: &v1::FinishedCheck) -> Vec<(&'static str, String)> {
    let now = s.answered_at;
    let when = |at: Option<i64>, none: &str| {
        at.map_or_else(|| none.to_string(), |at| screen.time(at, now))
    };
    let mut parts: Vec<(&'static str, String)> = Vec::new();
    if let Some(e) = &s.estate {
        let mut line = format!(
            "{}, {}.",
            count(e.checkouts, "checkout", "checkouts"),
            count(e.components, "component", "components")
        );
        if e.servers == 0 {
            line.push_str(" No servers known");
        } else {
            line.push_str(&format!(
                " {} known, {} offered for the sweep, {} read",
                count(e.servers, "server", "servers"),
                grouped(e.servers_offered),
                grouped(e.servers_read)
            ));
        }
        if e.own_devices > 0 {
            line.push_str(&format!(
                "; {} of your other devices seen in the private network, not read",
                grouped(e.own_devices)
            ));
        }
        if e.other_devices > 0 {
            line.push_str(&format!(
                "; {} seen in the private network, not read",
                count(
                    e.other_devices,
                    "other person's device",
                    "other people's devices"
                )
            ));
        }
        if e.machines_set_aside > 0 {
            line.push_str(&format!(
                "; {} retired or disowned by the owner",
                grouped(e.machines_set_aside)
            ));
        }
        line.push('.');
        if !e.machines_seen_after_owner_word_text.is_empty() {
            let seen: Vec<String> = e
                .machines_seen_after_owner_word_text
                .iter()
                .map(|m| Name::given(m).quoted())
                .collect();
            line.push_str(&format!(
                " Seen alive after the owner's word: {}.",
                seen.join(", ")
            ));
        }
        parts.push(("Estate", line));
    }
    if let Some(r) = &f.readings {
        let mut gaps = Vec::new();
        if r.machines_unread > 0 {
            gaps.push(format!(
                "{} could not be read",
                count(r.machines_unread, "machine", "machines")
            ));
        }
        if r.partial > 0 {
            gaps.push(format!(
                "{} partial",
                count(r.partial, "reading was", "readings were")
            ));
        }
        if r.failed > 0 {
            gaps.push(format!(
                "{} nothing",
                count(r.failed, "reading read", "readings read")
            ));
        }
        if r.not_repeated > 0 {
            gaps.push(format!(
                "{} not repeated",
                count(
                    r.not_repeated,
                    "earlier reading was",
                    "earlier readings were"
                )
            ));
        }
        if !gaps.is_empty() {
            parts.push(("Gaps", gaps.join("; ")));
        }
    }
    parts.push((
        "Changes",
        match &f.since_previous_run {
            None => "first run".to_string(),
            Some(c) => {
                let counts = format!(
                    "+{} added, {} changed, {} removed",
                    grouped(c.added),
                    grouped(c.changed),
                    grouped(c.removed)
                );
                if !f.unknown.is_empty() {
                    format!("since last run: {counts}; {}", f.unknown.join(", "))
                } else if c.added + c.changed + c.removed == 0 {
                    "none since last run".to_string()
                } else {
                    format!("since last run: {counts}")
                }
            }
        },
    ));
    if f.set_aside > 0 {
        parts.push((
            "Set aside",
            format!(
                "{} as no longer read by this version, not counted as removed",
                count(f.set_aside, "fact", "facts")
            ),
        ));
    }
    parts.push((
        "Watched places",
        match &s.watched {
            None => "never read".to_string(),
            Some(w) => {
                let files = count(w.files, "file", "files");
                let mut said = match (w.first_reading, &w.since_last_reading) {
                    (false, Some(c)) => format!(
                        "{files}, {} new, {} changed, {} gone since the last reading",
                        c.new, c.changed, c.gone
                    ),
                    _ => format!("{files}, first reading, kept as the baseline"),
                };
                let full = v1::Completeness::Full as i32;
                let not_full: Vec<String> = w
                    .kinds
                    .iter()
                    .filter(|k| k.coverage.is_some_and(|c| c != full))
                    .map(|k| {
                        format!(
                            "{} ({})",
                            k.kind,
                            if k.coverage == Some(v1::Completeness::Partial as i32) {
                                "partial"
                            } else {
                                "nothing read"
                            }
                        )
                    })
                    .chain((w.content_not_read > 0).then(|| {
                        format!(
                            "the content of {}",
                            count(w.content_not_read, "file", "files")
                        )
                    }))
                    .collect();
                if !not_full.is_empty() {
                    said.push_str(&format!("; not read in full: {}", not_full.join(", ")));
                }
                let presence: u64 = w.kinds.iter().map(|k| k.presence_only).sum();
                if let Some(note) = w.kinds.iter().find_map(|k| k.presence_only_note.as_ref()) {
                    said.push_str(&format!(
                        "; {} watched only for presence: {note}",
                        count(presence, "entry", "entries")
                    ));
                }
                said
            }
        },
    ));
    parts.push((
        "Installed software",
        match &s.integrity {
            None => "never read".to_string(),
            Some(i) => {
                let counted = format!(
                    "{}, {}, {}",
                    count(i.bundles, "application bundle", "application bundles"),
                    count(i.homebrew_kegs, "Homebrew keg", "Homebrew kegs"),
                    count(
                        i.global_npm_packages,
                        "global npm package",
                        "global npm packages"
                    )
                );
                let mut said = if i.first_reading {
                    format!("{counted}, first reading, kept as the baseline")
                } else {
                    format!(
                        "{counted}, {} changed while the version stayed, since the last reading",
                        i.changed_while_version_stayed
                    )
                };
                if let Some(apps) = not_verifying(i) {
                    said.push_str(&format!(
                        "; {apps}, which kept them as the baseline: a change of their seal or signer while the version stays is a finding, and {LISTS_SEALS} lists each with its seal"
                    ));
                }
                let not_full: Vec<String> = i
                    .readings
                    .iter()
                    .filter(|r| r.completeness != v1::Completeness::Full as i32)
                    .map(|r| {
                        format!(
                            "{} ({})",
                            r.kind,
                            if r.completeness == v1::Completeness::Partial as i32 {
                                "partial"
                            } else {
                                "nothing read"
                            }
                        )
                    })
                    .collect();
                if !not_full.is_empty() {
                    said.push_str(&format!("; not read in full: {}", not_full.join(", ")));
                }
                said
            }
        },
    ));
    if let Some(t) = &s.threats {
        let held = |n: u64| count(n, "exploited vulnerability", "exploited vulnerabilities");
        let judged = "matched against nothing in this estate but through the vulnerability records linked to them, so whether any of them affects this estate is not known from it";
        parts.push((
            "CISA catalogue",
            match (v1::FeedOutcome::try_from(t.outcome), t.entries) {
                (Ok(v1::FeedOutcome::Read), Some(n)) if t.first_reading == Some(true) => {
                    format!("{}, first reading, kept as the baseline; {judged}", held(n))
                }
                (Ok(v1::FeedOutcome::Read | v1::FeedOutcome::Unchanged), Some(n)) => format!(
                    "{}, {} new since the last reading{}; {judged}",
                    held(n),
                    grouped(t.new.unwrap_or_default()),
                    match t.gone {
                        Some(g) if g > 0 => format!(", {} left the catalogue", grouped(g)),
                        _ => String::new(),
                    }
                ),
                (Ok(v1::FeedOutcome::Failed), Some(n)) => format!(
                    "not read: {}; what is new is unknown, and the {} it held at its last reading, {}, are {judged}",
                    Said::given(t.reason_text.as_deref().unwrap_or_default()).quoted(),
                    held(n),
                    when(t.read_at, "an unknown time")
                ),
                (Ok(v1::FeedOutcome::Failed), None) => format!(
                    "not read: {}; the program knows no exploited vulnerability yet, so whether any affects this estate is unknown",
                    Said::given(t.reason_text.as_deref().unwrap_or_default()).quoted()
                ),
                _ => "never read; the program knows no exploited vulnerability yet, so whether any affects this estate is unknown".to_string(),
            },
        ));
    }
    if let Some(d) = &s.vulnerability_data {
        let clauses: Vec<String> = d
            .feeds
            .iter()
            .map(|f| {
                let held = format!(
                    "{}, {} of them on malicious packages",
                    count(f.records.unwrap_or_default(), "record", "records"),
                    grouped(f.malicious_records.unwrap_or_default())
                );
                let since = f.changed_at.or(f.read_at).map_or_else(
                    || "since an unknown time".to_string(),
                    |at| screen.since(at, now),
                );
                match v1::FeedOutcome::try_from(f.outcome) {
                    Ok(v1::FeedOutcome::NeverRead) => format!("{} never read", f.ecosystem),
                    Ok(v1::FeedOutcome::Read) => match (&f.since_last_reading, f.first_reading) {
                        (_, Some(true)) => {
                            format!(
                                "{}: {held}, first reading, kept as the baseline",
                                f.ecosystem
                            )
                        }
                        (Some(c), _) => format!(
                            "{}: {held}, {} new and {} changed since the last reading{}{}",
                            f.ecosystem,
                            grouped(c.new),
                            grouped(c.changed),
                            if c.withdrawn > 0 {
                                format!(", {} withdrawn", grouped(c.withdrawn))
                            } else {
                                String::new()
                            },
                            if c.gone > 0 {
                                format!(", {} left it", grouped(c.gone))
                            } else {
                                String::new()
                            }
                        ),
                        _ => format!("{}: {held}", f.ecosystem),
                    },
                    Ok(v1::FeedOutcome::Unchanged) => {
                        format!("{}: {held}, unchanged {since}", f.ecosystem)
                    }
                    _ => {
                        let reason =
                            Said::given(f.reason_text.as_deref().unwrap_or_default()).quoted();
                        match f.read_at {
                            Some(at) => format!(
                                "{} not read: {reason}; the {held}, read {}, stay in force",
                                f.ecosystem,
                                screen.time(at, now)
                            ),
                            None => format!(
                                "{} not read: {reason}; nothing of it is known yet",
                                f.ecosystem
                            ),
                        }
                    }
                }
            })
            .zip(&d.feeds)
            .map(|(said, f)| match v1::FeedOutcome::try_from(f.outcome) {
                Ok(v1::FeedOutcome::NeverRead) => said,
                _ => said + &crate::osv::not_compared(&f.ecosystem, f.matched),
            })
            .collect();
        let mut matched = String::new();
        if let Some(v) = &s.vulnerabilities {
            let (found, scope) = crate::covered::Found::of(v.projects_found.as_ref());
            let projects = s.estate.as_ref().map(|e| e.checkouts);
            matched = format!("; {}", crate::text::Matched::of(v).said(found, projects));
            // The one line of scope, after the count.
            if let Some(line) = scope {
                matched.push_str(&format!(". {}", line.trim_end_matches('.')));
            }
        }
        parts.push(("OSV data", format!("{}{matched}", clauses.join("; "))));
    }
    parts
}

/// A table under a label of its own, as `--coverage` sets each.
fn titled_table(
    screen: &Screen,
    out: &mut Vec<String>,
    label: &str,
    columns_of: &[Column],
    head: &[&str],
    rows: &[Vec<Cell>],
) {
    out.push(String::new());
    out.extend(
        screen
            .headline(label, BOLD, None)
            .into_iter()
            .map(|l| format!("  {l}")),
    );
    if rows.is_empty() {
        out.push("    none".to_string());
    } else {
        out.extend(screen.table(4, columns_of, Some(head), rows));
    }
}

fn coverage_text(s: &v1::Status, screen: &Screen, out: &mut Vec<String>) {
    let now = s.answered_at;
    let headline = match &s.coverage {
        Some(c) if c.failed > 0 => format!(
            "{} of {} full, {} failed",
            grouped(c.full),
            count(c.readings, "reading", "readings"),
            grouped(c.failed)
        ),
        Some(c) => format!(
            "{} of {} full",
            grouped(c.full),
            count(c.readings, "reading", "readings")
        ),
        None => "Nothing has been read yet".to_string(),
    };
    let style = match &s.coverage {
        Some(c) if c.failed == 0 => BOLD,
        _ => YELLOW.bold(),
    };
    out.extend(screen.headline(&headline, style, checked(screen, s).as_deref()));
    out.push(String::new());
    let mut lines: Vec<(&str, String, Style)> = Vec::new();
    let store = s.store.clone().unwrap_or_default();
    lines.push(("Store", Name::given(&store.path_text).bare(), PLAIN));
    match &s.last_run {
        None => lines.push(("Last run", "none has started".to_string(), YELLOW)),
        Some(l) => match l.finished_at {
            Some(at) => lines.push((
                "Last run",
                format!(
                    "started {}, finished {}",
                    screen.time(l.started_at, now),
                    screen.time(at, now)
                ),
                PLAIN,
            )),
            None => {
                let (said, style) = unfinished(s, screen, l.started_at);
                lines.push(("Last run", said, style));
            }
        },
    }
    match &s.last_finished_run {
        None => lines.push((
            "Last check",
            "none has finished yet, so nothing of a check is counted".to_string(),
            YELLOW,
        )),
        Some(f) => {
            let check = f.check.clone().unwrap_or_default();
            if s.last_run.as_ref().is_some_and(|l| l.id != check.id) {
                lines.push((
                    "Counted",
                    format!(
                        "by the run that finished {}",
                        screen.time(check.finished_at.unwrap_or(check.started_at), now)
                    ),
                    PLAIN,
                ));
            }
            for (label, value) in counted(screen, s, f) {
                lines.push((label, unstopped(&value).to_string(), PLAIN));
            }
        }
    }
    let mut watched: Vec<Vec<Cell>> = Vec::new();
    match &s.this_mac {
        None => lines.push((
            "This Mac",
            "whether it is watched is not said".to_string(),
            YELLOW,
        )),
        Some(m) => {
            let (state, style) = watching(s, screen);
            let state = match state.split_once("; ") {
                Some(("yes", rest)) => format!("watched; {rest}"),
                Some(("in part", rest)) => format!("watched in part; {rest}"),
                _ => state,
            };
            lines.push((
                "This Mac",
                format!(
                    "{state}; last checked {}",
                    m.checked_at
                        .map_or_else(|| "never".to_string(), |at| screen.time(at, now))
                ),
                style,
            ));
            if let Some(said) = not_fresh(s, screen) {
                lines.push(("Not fresh", said, YELLOW));
            }
            watched = m
                .watched
                .iter()
                .map(|w| {
                    vec![
                        Cell::plain(w.what.clone()),
                        Cell::new(grouped(w.count), BOLD),
                        Cell::plain(w.how.clone()),
                    ]
                })
                .collect();
        }
    }
    if let Some(l) = &s.event_level {
        // A collector installed that does not run red, one that runs with a note yellow.
        let running = l.state == v1::CollectorState::Running as i32;
        let noted = l.in_words.as_ref().is_some_and(|w| !w.notes.is_empty());
        let style = match (running, l.state == v1::CollectorState::NotInstalled as i32) {
            (false, false) => RED,
            _ if noted => YELLOW,
            _ => PLAIN,
        };
        lines.push(("Event level", event_level_long(l), style));
    }
    match &s.needs_a_look {
        None => lines.push((
            "Needs a look",
            "not known yet, no run of this build has looked for findings in this store yet"
                .to_string(),
            BOLD,
        )),
        Some(n) => lines.push((
            "Needs a look",
            needing(n.total, n.urgent_total),
            if n.total > 0 { RED } else { PLAIN },
        )),
    }
    let width = lines
        .iter()
        .map(|(l, ..)| screen::columns(l))
        .max()
        .unwrap_or(0);
    for (label, value, style) in &lines {
        out.extend(screen.labelled(2, width, label, value, *style, None, 0));
    }
    // What is watched on this Mac: each kind of place, how many and how often.
    if !watched.is_empty() {
        titled_table(
            screen,
            out,
            "Watched",
            &[
                Column::new(Cut::End),
                Column::right(Cut::Never),
                Column::new(Cut::Never),
            ],
            &["Place", "How many", "How often"],
            &watched,
        );
    }
    // Every cause in two groups: what should work here and does not now, the faults the default
    // status says, each cause of them whole; and the limits of this version here.
    let (failed, limits): (Vec<&v1::Uncovered>, Vec<&v1::Uncovered>) =
        s.not_covered.iter().partition(|u| u.fault);
    let others = faults(s, screen, false);
    if !others.is_empty() || !failed.is_empty() {
        out.push(String::new());
        out.push(format!("  {}", screen.paint(BOLD, "Faults")));
        for f in &others {
            out.extend(fault_lines(screen, 4, f));
        }
        cause_section(screen, out, "", &failed);
    }
    if !limits.is_empty() {
        out.push(String::new());
        cause_section(screen, out, "Limits of this version here", &limits);
    }
    if let Some(c) = &s.coverage {
        out.push(String::new());
        out.extend(screen.labelled(
            2,
            8,
            "Readings",
            &format!(
                "{} at the latest check: {} full, {} failed, {} with no reader, {} where the source does not give it, {} with nothing to read, {} implied by {}",
                grouped(c.readings),
                grouped(c.full),
                grouped(c.failed),
                grouped(c.no_reader),
                grouped(c.not_given),
                grouped(c.read_nothing),
                grouped(c.implied_by_unreached),
                count(
                    c.unreached_total,
                    "machine that could not be reached",
                    "machines that could not be reached"
                )
            ),
            if c.failed > 0 { YELLOW } else { PLAIN },
            None,
            0,
        ));
        if !c.unreached.is_empty() {
            let rows: Vec<Vec<Cell>> = c
                .unreached
                .iter()
                .map(|u| {
                    vec![
                        Cell::new(Name::given(machine_name(&u.scope_text)).bare(), RED),
                        Cell::plain(screen.time(u.since_at, now)),
                        Cell::plain(
                            Said::given(u.reason_text.as_deref().unwrap_or_default()).quoted(),
                        ),
                    ]
                })
                .collect();
            titled_table(
                screen,
                out,
                "Machines not reached",
                &[
                    Column::new(Cut::Middle),
                    Column::new(Cut::Never),
                    Column::new(Cut::End),
                ],
                &["Machine", "Since", "Why"],
                &rows,
            );
            let more = c.unreached_total.saturating_sub(c.unreached.len() as u64);
            if more > 0 {
                out.push(format!(
                    "    {} not listed",
                    count(more, "more machine", "more machines")
                ));
            }
        }
        let shown: Vec<&v1::ReadingGroup> = c
            .problems
            .iter()
            .filter(|g| g.class != v1::ReadingClass::ReadNothing as i32)
            .collect();
        if !shown.is_empty() {
            let rows: Vec<Vec<Cell>> = shown
                .iter()
                .map(|g| {
                    let failed = g.class == v1::ReadingClass::Failed as i32
                        || v1::ReadingClass::try_from(g.class).is_err()
                        || g.class == v1::ReadingClass::Unspecified as i32;
                    vec![
                        Cell::new(
                            words::<v1::ReadingClass>(g.class),
                            if failed { RED } else { PLAIN },
                        ),
                        Cell::plain(g.reader.clone()),
                        Cell::plain(g.kind.clone()),
                        Cell::new(grouped(g.count), BOLD),
                        Cell::plain(
                            g.examples_text
                                .first()
                                .map(|e| Name::given(machine_name(e)).bare())
                                .unwrap_or_default(),
                        ),
                        Cell::plain(
                            Said::given(g.reason_text.as_deref().unwrap_or_default()).quoted(),
                        ),
                    ]
                })
                .collect();
            titled_table(
                screen,
                out,
                "Readings that were not full",
                &[
                    Column::new(Cut::Never),
                    Column::new(Cut::Never),
                    Column::new(Cut::End),
                    Column::right(Cut::Never),
                    Column::new(Cut::Middle).giving(2),
                    Column::new(Cut::End).giving(1),
                ],
                &["Class", "Reader", "What", "Readings", "For example", "Why"],
                &rows,
            );
            let more = c.problems_total.saturating_sub(c.problems.len() as u64);
            if more > 0 {
                out.push(format!(
                    "    {} not listed",
                    count(more, "more group of readings", "more groups of readings")
                ));
            }
        }
    }
    if let Some(list) = s.no_reader_for.as_ref().filter(|l| !l.items.is_empty()) {
        let rows: Vec<Vec<Cell>> = list
            .items
            .iter()
            .map(|r| {
                vec![
                    Cell::plain(r.what.clone()),
                    Cell::plain(Name::given(r.what_text.as_deref().unwrap_or_default()).bare()),
                    Cell::new(grouped(r.where_count), BOLD),
                ]
            })
            .collect();
        titled_table(
            screen,
            out,
            "No reader in this build for",
            &[
                Column::new(Cut::End),
                Column::new(Cut::End),
                Column::right(Cut::Never),
            ],
            &["What", "Which", "Places"],
            &rows,
        );
    }
    if let Some(w) = &s.watched {
        let rows: Vec<Vec<Cell>> = w
            .changes
            .iter()
            .map(|c| {
                vec![
                    Cell::new(screen.time(c.at, now), DIM),
                    Cell::plain(words::<v1::Change>(c.change)),
                    Cell::plain(c.kind.clone()),
                    Cell::plain(Name::given(&c.path_text).bare()),
                ]
            })
            .collect();
        titled_table(
            screen,
            out,
            &format!(
                "Latest changes in watched places, newest first, {} of {}",
                grouped(rows.len() as u64),
                grouped(w.changes_total)
            ),
            &[
                Column::new(Cut::Never),
                Column::new(Cut::Never),
                Column::new(Cut::End).giving(1),
                Column::new(Cut::Middle),
            ],
            &["When", "Change", "Kind", "Path"],
            &rows,
        );
    }
    out.push(String::new());
    out.push(screen.next("immunity status --json", "gives all of it, with every list"));
}

/// What tells a finding from its neighbours in a list, as a cell: the package and its releases
/// in their project for a finding about a package, kept whole while the project's folder is cut;
/// what it is about and where for one whose thing no name says; where it is for the others.
fn telling(l: &v1::ListedFinding) -> Cell {
    if let Some(p) = &l.package_text {
        // The project's folder: the lockfile's path without its line or entry, then its folder.
        let file = l
            .where_text
            .split_once('#')
            .map_or(l.where_text.as_str(), |(f, _)| f);
        let folder = file.rsplit_once('/').map_or(file, |(d, _)| d);
        let releases = crate::text::names(&l.releases_text, ", ");
        let p = Name::given(p).quoted();
        let package = if releases.is_empty() {
            format!("{p} in ")
        } else {
            format!("{p} {releases} in ")
        };
        let keep = screen::columns(&view::shown(&package));
        return Cell::plain(format!("{package}{}", Name::given(folder).quoted())).keeping(keep);
    }
    Cell::plain(match &l.thing {
        Some(t) => format!("{t} on {}", Name::given(&l.where_text).quoted()),
        None if l.where_text.is_empty() => String::new(),
        // Quoted also alone: the same words follow a title in the status's sentence.
        None => Name::given(&l.where_text).quoted(),
    })
}

/// `immunity findings` for a person: the open findings, or every one with `all`, grouped under
/// their level, most urgent first.
pub fn findings(f: &v1::Findings, all: bool, screen: &Screen) -> String {
    let mut out: Vec<String> = Vec::new();
    let open = v1::FindingState::Open as i32;
    let state_of = |l: &v1::ListedFinding| l.finding.as_ref().map_or(open, |r| r.state);
    // A state this build does not know is read as open, as the schema says.
    let is_open = |l: &v1::ListedFinding| {
        let s = state_of(l);
        s == open
            || v1::FindingState::try_from(s).is_err()
            || s == v1::FindingState::Unspecified as i32
    };
    let urgent = |l: &v1::ListedFinding| l.finding.as_ref().is_some_and(|r| r.urgent);
    // Open findings first, each part in the answer's order, so a cut never hides an open
    // finding behind a closed one.
    let (mut shown, closed): (Vec<&v1::ListedFinding>, Vec<&v1::ListedFinding>) =
        f.findings.iter().partition(|l| is_open(l));
    let open_count = shown.len() as u64;
    let urgent_count = shown.iter().filter(|l| urgent(l)).count() as u64;
    if all {
        shown.extend(closed);
    }
    let severity = |l: &v1::ListedFinding| l.finding.as_ref().and_then(|r| r.severity);
    // Per level, the most severe first, over the findings listed.
    let mut levels: Vec<(u8, String, Style, u64)> = Vec::new();
    for l in &shown {
        let (word, style) = level(severity(l));
        let r = rank(severity(l));
        match levels.iter_mut().find(|(_, w, ..)| *w == word) {
            Some(entry) => entry.3 += 1,
            None => levels.push((r, word, style, 1)),
        }
    }
    levels.sort_by_key(|a| std::cmp::Reverse(a.0));
    let by_level: Vec<String> = levels
        .iter()
        .map(|(_, w, _, n)| format!("{} {w}", grouped(*n)))
        .collect();
    let urgent_said = match urgent_count {
        0 => "none urgent".to_string(),
        u => format!("{} urgent", grouped(u)),
    };
    let mut answer = if all {
        match shown.len() {
            0 => "No findings".to_string(),
            n => format!(
                "{}, {} open, {urgent_said}",
                count(n as u64, "finding", "findings"),
                grouped(open_count),
            ),
        }
    } else {
        match open_count {
            0 => "No open findings".to_string(),
            n => format!(
                "{}, {urgent_said}",
                count(n, "open finding", "open findings")
            ),
        }
    };
    if !by_level.is_empty() {
        answer.push_str(&format!(": {}", by_level.join(", ")));
    }
    let checked_at = f
        .latest_run_at
        .map(|at| format!("checked {}", screen.time(at, f.answered_at)));
    const NO_CHECK: &str = "No full check has finished. Only findings recorded so far are shown.";
    if open_count > 0 {
        out.extend(screen.headline(&format!("✗ {answer}"), RED.bold(), checked_at.as_deref()));
        if f.latest_run_at.is_none() {
            out.push(screen.paint(YELLOW, NO_CHECK));
        }
    } else if f.latest_run_at.is_some() {
        out.extend(screen.headline(&format!("✓ {answer}"), GREEN.bold(), checked_at.as_deref()));
    } else {
        // Nothing open and nothing has looked: what is missing comes first, never a calm line.
        out.extend(screen.headline(NO_CHECK, YELLOW.bold(), None));
        out.push(screen.paint(PLAIN, &answer));
    }
    if !shown.is_empty() {
        out.push(String::new());
        let listed = &shown[..shown.len().min(FINDINGS_SHOWN)];
        let with_state = listed.iter().any(|l| !is_open(l));
        // Under each level, the most severe first, the findings of one rule under the rule's name,
        // said once: groups with an urgent finding first, then the largest; within a group, the
        // answer's order.
        struct Group<'a> {
            rank: u8,
            level: (String, Style),
            rule: String,
            title: String,
            rows: Vec<&'a v1::ListedFinding>,
        }
        let mut groups: Vec<Group> = Vec::new();
        for l in listed {
            let rule = l
                .finding
                .as_ref()
                .and_then(|r| r.rule.clone())
                .unwrap_or_default();
            let title = short_title(
                screen,
                l.rule_title_text.as_deref(),
                &l.short_title,
                &l.title,
            );
            let level = level(severity(l));
            match groups
                .iter_mut()
                .find(|g| g.rule == rule && g.title == title && g.level.0 == level.0)
            {
                Some(g) => g.rows.push(l),
                None => groups.push(Group {
                    rank: rank(severity(l)),
                    level,
                    rule,
                    title,
                    rows: vec![l],
                }),
            }
        }
        // Then by rule, as the status orders its rules.
        groups.sort_by_key(|g| {
            (
                std::cmp::Reverse(g.rank),
                !g.rows.iter().any(|l| urgent(l)),
                std::cmp::Reverse(g.rows.len()),
                g.rule.clone(),
            )
        });
        // Under a rule's name, the findings of one group (`group`, equal and present) that share
        // urgency and state are one line: drawing only, every finding still named by its id.
        // A line of several says their folder, so one without it is never folded; one with a
        // verdict of the response layer stays a row of its own, as on the pages.
        let key = |l: &v1::ListedFinding| {
            let group = l
                .group
                .clone()
                .filter(|_| l.folder_text.is_some() && l.verdicts.is_none())?;
            Some((group, urgent(l), state_of(l)))
        };
        let lines_of: Vec<Vec<Vec<&v1::ListedFinding>>> = groups
            .iter()
            .map(|g| {
                let mut lines: Vec<Vec<&v1::ListedFinding>> = Vec::new();
                for l in &g.rows {
                    match lines
                        .iter_mut()
                        .find(|line| key(l).is_some() && key(line[0]) == key(l))
                    {
                        Some(line) => line.push(l),
                        None => lines.push(vec![l]),
                    }
                }
                lines
            })
            .collect();
        let with_change = listed.iter().any(|l| l.change.is_some());
        // One table for every line, so the columns line up down the page.
        let rows: Vec<Vec<Cell>> = lines_of
            .iter()
            .flatten()
            .map(|line| {
                let (l, n) = (line[0], line.len() as u64);
                let r = l.finding.clone().unwrap_or_default();
                let mut row = vec![match n {
                    1 => Cell::new(r.id.clone(), DIM),
                    n => Cell::new(count(n, "finding", "findings"), BOLD),
                }];
                if with_state {
                    row.push(Cell::plain(words::<v1::FindingState>(r.state)));
                }
                if with_change {
                    let said = l.change.map_or("", crate::finding_text::change_said);
                    row.push(Cell::plain(said));
                }
                row.push(match &l.folder_text {
                    Some(folder) if n > 1 => Cell::plain(Name::given(folder).bare()),
                    _ => telling(l),
                });
                row.push(Cell::new(if r.urgent { "urgent" } else { "" }, RED));
                row
            })
            .collect();
        let mut columns_of = vec![Column::new(Cut::Never)];
        if with_state {
            columns_of.push(Column::new(Cut::Never));
        }
        if with_change {
            columns_of.push(Column::new(Cut::Never));
        }
        columns_of.extend([Column::new(Cut::Middle), Column::new(Cut::Never)]);
        let mut lines = screen.table(4, &columns_of, None, &rows).into_iter();
        let mut last_level: Option<String> = None;
        for (g, folded) in groups.iter().zip(&lines_of) {
            if last_level.as_deref() != Some(g.level.0.as_str()) {
                if last_level.is_some() {
                    out.push(String::new());
                }
                out.push(screen.paint(g.level.1.bold(), &g.level.0));
                last_level = Some(g.level.0.clone());
            }
            // Findings, never lines; with folded lines under it, both.
            let n = match folded.len() {
                l if l == g.rows.len() => grouped(l as u64),
                l => format!(
                    "{} in {}",
                    count(g.rows.len() as u64, "finding", "findings"),
                    count(l as u64, "line", "lines")
                ),
            };
            // A title from a core that gives no short one is a sentence, cut to fit on a terminal.
            let title = match screen.fits() {
                Some(w) => screen::cut_end(
                    &view::shown(&g.title),
                    w.saturating_sub(5 + screen::columns(&n)),
                ),
                None => g.title.clone(),
            };
            out.push(format!(
                "  {}   {}",
                screen.paint(PLAIN, &title),
                screen.paint(BOLD, &n)
            ));
            for line in folded {
                let drawn = lines.next().unwrap_or_default();
                out.push(drawn);
                if line.len() == 1 {
                    continue;
                }
                // Every id whole, under the line, so the folder ends its own line as a path does
                // and the ids' lines hold nothing from the Mac: one line in a pipe, wrapped on a
                // terminal.
                let ids: Vec<String> = line
                    .iter()
                    .map(|l| l.finding.as_ref().map_or(String::new(), |r| r.id.clone()))
                    .collect();
                let width = screen.fits().map(|w| w.saturating_sub(6));
                for l in screen::wrap(&ids.join(", "), width) {
                    out.push(format!("      {}", screen.paint(DIM, &l)));
                }
            }
        }
    }
    if shown.len() > FINDINGS_SHOWN {
        let hidden = &shown[FINDINGS_SHOWN..];
        let urgent = hidden.iter().filter(|l| urgent(l)).count();
        out.push(String::new());
        for l in screen::wrap(
            &format!(
                "Showing the first {FINDINGS_SHOWN}; {} more not shown, {} of them urgent. Use --json or --proto for the full list.",
                grouped(hidden.len() as u64),
                grouped(urgent as u64)
            ),
            screen.fits(),
        ) {
            out.push(screen.paint(if urgent > 0 { RED } else { PLAIN }, &l));
        }
    }
    out.push(String::new());
    out.push(screen.next("immunity finding <id>", "shows one and how to answer it"));
    joined(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::visible;

    /// The text of a status made by hand, with the headline `status::message` would give it,
    /// computed from the message as it stands.
    fn status(s: &v1::Status, screen: &Screen, coverage: bool) -> String {
        super::status(&crate::headline::headed(s.clone()), screen, coverage)
    }

    /// The same for the text of `immunity run`.
    fn ran(s: &v1::Status, screen: &Screen) -> String {
        crate::after_run::run(&crate::headline::headed(s.clone()), screen)
    }

    /// When the invented answers were made, and a check that finished three minutes before.
    const NOW: i64 = 1_794_807_960;
    const CHECKED: i64 = NOW - 180;
    /// A style sequence, a title sequence and a right-to-left override, as a name may hold them.
    const ODD: &str = "shop\u{1b}[31mRED\u{1b}[0m\u{202e}evil\u{1b}]0;owned\u{7}title";
    /// A path longer than any terminal.
    const LONG: &str = "~/Developer/clients/northwind-traders/customer-portal-frontend-monorepo-with-a-very-long-name/package-lock.json#node_modules/@ctrl/tinycolor";

    /// The screens a text is rendered for.
    fn screens() -> Vec<Screen> {
        let mut out = vec![Screen::pipe()];
        for width in [60, 80, 120] {
            out.push(Screen::terminal(width, true));
            out.push(Screen::terminal(width, false));
        }
        out
    }

    /// The class the core gives the cause with this id.
    fn class_of(id: &str) -> v1::Cause {
        let cause = crate::covered::CAUSES
            .iter()
            .find(|c| c.id == id)
            .unwrap_or_else(|| panic!("no cause {id}"));
        crate::status::cause_class(cause.class)
    }

    fn uncovered(
        id: &str,
        who: &str,
        every_mac: bool,
        title: &str,
        names: &[(&str, Option<&str>)],
    ) -> v1::Uncovered {
        v1::Uncovered {
            id: id.to_string(),
            who: who.to_string(),
            class: class_of(id) as i32,
            // As the core gives a cause that no reading of this Mac sorts.
            fault: class_of(id) == v1::Cause::Failed,
            title: title.to_string(),
            holds_on: if every_mac {
                v1::HoldsOn::EveryMac as i32
            } else {
                v1::HoldsOn::ThisMac as i32
            },
            examples_text: names.iter().map(|(n, _)| n.to_string()).collect(),
            examples: names
                .iter()
                .map(|(n, r)| v1::UncoveredExample {
                    name_text: n.to_string(),
                    reason_text: r.map(str::to_string),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn group(rule: &str, level: v1::Level, count: u64, urgent: u64) -> v1::RuleCount {
        v1::RuleCount {
            rule: rule.to_string(),
            short_title: format!("Short title of {rule}"),
            rule_title_text: None,
            severity: Some(level as i32),
            count,
            urgent,
        }
    }

    /// A status of real size: every part a status can carry, counts of seven digits, long paths,
    /// and `odd` in every text from a source.
    fn status_of(odd: &str) -> v1::Status {
        let long = format!("{LONG}/{odd}");
        v1::Status {
            answered_at: NOW,
            store: Some(v1::StoreFile {
                path_text: format!(
                    "/Users/example/Library/Application Support/ai.nuanu.immunity.core/{odd}/store.db"
                ),
                exists: true,
                ..Default::default()
            }),
            last_run: Some(v1::CheckMark {
                id: "run-2".to_string(),
                started_at: NOW - 600,
                finished_at: None,
            }),
            running: false,
            last_finished_run: Some(v1::FinishedCheck {
                check: Some(v1::CheckMark {
                    id: "run-1".to_string(),
                    started_at: CHECKED - 30,
                    finished_at: Some(CHECKED),
                }),
                readings: Some(v1::CheckReadings {
                    partial: 1_234_567,
                    failed: 14,
                    not_repeated: 2,
                    machines_unread: 1,
                }),
                since_previous_run: Some(v1::SinceCheck {
                    added: 1_000_000,
                    changed: 3,
                    removed: 0,
                }),
                unknown: vec!["removals unknown where a reading was partial".to_string()],
                set_aside: 2,
                ..Default::default()
            }),
            estate: Some(v1::Estate {
                checkouts: 1_234_567,
                components: 7_654_321,
                servers: 9,
                servers_offered: 7,
                servers_read: 2,
                machines_set_aside: 2,
                machines_seen_after_owner_word_text: vec![odd.to_string()],
                ..Default::default()
            }),
            watched: Some(v1::WatchedPlaces {
                files: 1_234_567,
                since_last_reading: Some(v1::PlaceCounts {
                    new: 1,
                    changed: 2,
                    gone: 3,
                }),
                kinds: vec![v1::WatchedKind {
                    kind: "authentication module".to_string(),
                    coverage: Some(v1::Completeness::Partial as i32),
                    ..Default::default()
                }],
                changes: (0..50)
                    .map(|i| v1::PlaceChange {
                        at: CHECKED - i,
                        change: v1::Change::New as i32,
                        kind: "script run when a project's packages are installed".to_string(),
                        path_text: format!("{long}/{i}"),
                        ..Default::default()
                    })
                    .collect(),
                changes_total: 1_234_567,
                ..Default::default()
            }),
            threats: Some(v1::Threats {
                outcome: v1::FeedOutcome::Failed as i32,
                entries: Some(1_234_567),
                read_at: Some(NOW - 90_000),
                reason_text: Some(format!("curl: (6) Could not resolve host {odd}")),
                ..Default::default()
            }),
            vulnerability_data: Some(v1::VulnerabilityData {
                matched: true,
                feeds: vec![v1::FeedState {
                    ecosystem: "npm".to_string(),
                    outcome: v1::FeedOutcome::Unchanged as i32,
                    records: Some(1_234_567),
                    malicious_records: Some(4),
                    read_at: Some(CHECKED),
                    matched: true,
                    ..Default::default()
                }],
            }),
            vulnerabilities: Some(v1::VulnerabilityTotals {
                affected_records: 12,
                unknown_packages: 2,
                ..Default::default()
            }),
            integrity: Some(v1::Integrity {
                bundles: 4,
                homebrew_kegs: 8,
                global_npm_packages: 4,
                bundles_not_verifying: 4,
                not_verifying_since_first_reading: 4,
                ..Default::default()
            }),
            no_reader_for: Some(v1::NoReaderFor {
                items: vec![v1::NoReader {
                    what: "lockfile kind".to_string(),
                    what_text: Some(odd.to_string()),
                    where_count: 1_234_567,
                }],
            }),
            coverage: Some(v1::CoverageSummary {
                readings: 9_999_999,
                full: 9_876_543,
                failed: 1_234_567,
                no_reader: 9,
                problems: vec![v1::ReadingGroup {
                    class: v1::ReadingClass::Failed as i32,
                    reader: "watched-places".to_string(),
                    kind: "PAM policies and modules, and authorization plugins".to_string(),
                    reason_text: Some(format!("could not be read: {long} (Permission denied)")),
                    count: 1_234_567,
                    examples_text: vec![format!("checkout:machine:example-host/{odd}")],
                }],
                problems_total: 3,
                unreached: vec![v1::Unreached {
                    scope_text: format!("machine:{odd}"),
                    since_at: CHECKED - 3600,
                    reason_text: Some("the sweep of this server did not complete".to_string()),
                }],
                unreached_total: 1_234_567,
                ..Default::default()
            }),
            needs_a_look: Some(v1::NeedsALook {
                items: Vec::new(),
                total: 1_234_567,
                urgent_total: 765_432,
                by_rule: vec![
                    v1::RuleCount {
                        rule_title_text: Some(format!(
                            "A published rule whose own title is far longer than a short one {odd}"
                        )),
                        ..group("sigma:a", v1::Level::Critical, 1_000_000, 1_000_000)
                    },
                    group(
                        "lockfiles.exploited-vulnerability",
                        v1::Level::Critical,
                        3,
                        3,
                    ),
                    group("autorun.agent-start", v1::Level::High, 9, 9),
                    group("autorun.folder-open", v1::Level::High, 3, 2),
                    group("indicator.match", v1::Level::High, 2, 2),
                    group("integrity.package-files", v1::Level::High, 2, 2),
                    group("processes.detached-inline-code", v1::Level::High, 2, 2),
                    group("watched.git-hook", v1::Level::Medium, 234_000, 0),
                    v1::RuleCount {
                        severity: None,
                        ..group("kept.rule", v1::Level::Unspecified, 546, 0)
                    },
                ],
            }),
            this_mac: Some(v1::ThisMac {
                state: v1::ThisMacState::WatchedInPart as i32,
                live: false,
                checked_at: Some(CHECKED),
                watched: vec![v1::WatchedThing {
                    what: "startup items".to_string(),
                    count: 1_234_567,
                    how: "hourly".to_string(),
                }],
                fresh: false,
                stale_reason: Some("no full check has finished on this store".to_string()),
                ..Default::default()
            }),
            watching: Some(v1::Watcher {
                failed: vec![v1::WatcherFailure {
                    what: crate::watch::STORE.to_string(),
                    at: CHECKED,
                    detail_text: odd.to_string(),
                }],
                ..Default::default()
            }),
            event_level: Some(v1::EventLevel {
                state: v1::CollectorState::Running as i32,
                program_starts: Some(v1::Span {
                    since_check: 1,
                    last_day: 1_234_567,
                }),
                unknown_losses: Some(v1::Span {
                    since_check: 1,
                    last_day: 1,
                }),
                lost: Some(v1::Span {
                    since_check: 1,
                    last_day: 1_234_567,
                }),
                in_words: Some(v1::EventLevelWords {
                    state: "on".to_string(),
                    notes: vec![
                        "The collector restarted once; program starts in that moment were not seen."
                            .to_string(),
                        "1,234,567 program starts were missed because the collector fell behind."
                            .to_string(),
                    ],
                    caveats: vec![
                        v1::Caveat {
                            kind: "restarts".to_string(),
                            short: "1 restart".to_string(),
                        },
                        v1::Caveat {
                            kind: "lost".to_string(),
                            short: "1,234,567 lost".to_string(),
                        },
                    ],
                }),
                ..Default::default()
            }),
            not_covered: vec![
                uncovered(
                    "servers-not-checked",
                    "you",
                    false,
                    "1,234,567 of your servers were not checked last time.",
                    &[("staging-api", None), (odd, None)],
                ),
                uncovered(
                    "not-permitted",
                    "you",
                    false,
                    "1 file could not be opened because of its permissions.",
                    &[("example-host", Some(&format!("could not be read: {long}")))],
                ),
                uncovered(
                    "could-not-read",
                    "nothing",
                    false,
                    "2 things could not be read at the last check.",
                    &[("example-host", Some("sockets that could not be read: 1"))],
                ),
                uncovered(
                    "not-understood",
                    "nothing",
                    false,
                    "Some files and packages are not understood by this version yet.",
                    &[("poetry.lock", None), (odd, None), ("yarn.lock", None)],
                ),
                uncovered(
                    "vulnerabilities-unknown",
                    "nothing",
                    false,
                    "For 2 of the packages your projects use, this version cannot tell whether a known vulnerability affects them.",
                    &[],
                ),
                uncovered(
                    "persistence-not-read",
                    "nothing",
                    true,
                    "Some places where something can be set to start by itself on this Mac are not checked.",
                    &[],
                ),
            ],
            ..Default::default()
        }
    }

    fn listed(i: usize, level: v1::Level, urgent: bool, where_text: String) -> v1::ListedFinding {
        v1::ListedFinding {
            finding: Some(v1::FindingRef {
                id: format!("f{i:010x}"),
                rule: Some("watched.git-hook".to_string()),
                state: v1::FindingState::Open as i32,
                severity: Some(level as i32),
                urgent,
                ..Default::default()
            }),
            title: "A script that git runs by itself in one of your projects was added, changed or removed.".to_string(),
            short_title: "Script git runs by itself changed".to_string(),
            where_text,
            last_seen_at: CHECKED,
            ..Default::default()
        }
    }

    /// A list of real size: tens of findings of every level, long paths, a package, a published
    /// rule, and `odd` in every text from a source.
    fn findings_of(odd: &str) -> v1::Findings {
        let mut list: Vec<v1::ListedFinding> = Vec::new();
        for i in 0..7 {
            list.push(v1::ListedFinding {
                package_text: Some(format!("@ctrl/tinycolor-{odd}")),
                releases_text: vec!["4.1.1".to_string(), "4.1.2".to_string()],
                short_title: "Malicious package in a project".to_string(),
                ..listed(i, v1::Level::Critical, true, format!("{LONG}{i}"))
            });
        }
        list.push(v1::ListedFinding {
            rule_title_text: Some(format!(
                "Osacompile Execution By Potentially Suspicious Process {odd}"
            )),
            short_title: "Program start a published rule marks risky".to_string(),
            ..listed(7, v1::Level::High, true, "example-host".to_string())
        });
        for i in 8..40 {
            list.push(v1::ListedFinding {
                change: Some(v1::Change::Changed as i32),
                ..listed(
                    i,
                    v1::Level::High,
                    i % 2 == 0,
                    format!("~/dev/{odd}-{i}/.git/hooks/pre-commit"),
                )
            });
        }
        for i in 40..60 {
            let mut l = listed(i, v1::Level::Medium, false, format!("{LONG}/{i}"));
            // Ten of one group, folded under their folder, which holds `odd` too.
            if i >= 50 {
                l.group = Some("g1".to_string());
                l.folder_text = Some(format!("~/dev/{odd}/.git/hooks"));
                l.change = Some(v1::Change::NotRead as i32);
            }
            list.push(l);
        }
        let mut seen = listed(60, v1::Level::Low, false, "~/.zshrc".to_string());
        if let Some(r) = seen.finding.as_mut() {
            r.state = v1::FindingState::Seen as i32;
        }
        list.push(seen);
        v1::Findings {
            answered_at: NOW,
            latest_run_at: Some(CHECKED),
            findings: list,
            ..Default::default()
        }
    }

    /// Every text a person reads of these answers, on one screen.
    fn texts(screen: &Screen, odd: &str) -> Vec<String> {
        let s = status_of(odd);
        let f = findings_of(odd);
        vec![
            status(&s, screen, false),
            status(&s, screen, true),
            findings(&f, false, screen),
            findings(&f, true, screen),
        ]
    }

    #[test]
    fn no_line_is_longer_than_the_terminal_at_sixty_eighty_and_a_hundred_and_twenty_columns() {
        for screen in screens().into_iter().filter(|s| s.terminal) {
            let width = screen.width.unwrap();
            for text in texts(&screen, ODD) {
                for line in text.lines() {
                    assert!(
                        screen::columns(&visible(line)) <= width,
                        "{width}: {line:?}\n{text}"
                    );
                }
            }
        }
    }

    #[test]
    fn in_a_pipe_there_is_no_escape_byte_nothing_is_cut_and_times_are_exact() {
        let pipe = Screen::pipe();
        let all = texts(&pipe, ODD).concat();
        assert!(!all.contains('\u{1b}'), "{all}");
        // Whole: the longest path, a long reason, a published rule's own title.
        for whole in [
            format!("{LONG}/40"),
            format!("could not be read: {LONG}/{}", view::shown(ODD)),
            format!(
                "Osacompile Execution By Potentially Suspicious Process {}",
                view::shown(ODD)
            ),
        ] {
            assert!(all.contains(&whole), "{whole}\n{all}");
        }
        assert!(all.contains(&view::utc(CHECKED)), "{all}");
        assert!(!all.contains(" ago"), "{all}");
        // And on a terminal the same answers are cut and timed from now.
        let terminal = texts(&Screen::terminal(80, false), ODD).concat();
        assert!(!terminal.contains(&format!("{LONG}/40")));
        assert!(terminal.contains("checked 3 min ago"), "{terminal}");
    }

    /// Whether every escape byte of a text begins a style sequence of the program's own, every
    /// line closes each style it opens, and nothing a name held reached the terminal raw.
    fn styles_are_the_programs_own(text: &str) -> bool {
        let own = |seq: &str| {
            seq.strip_prefix("\u{1b}[")
                .and_then(|s| s.strip_suffix('m'))
                .is_some_and(|codes| {
                    codes
                        .split(';')
                        .all(|c| ["0", "1", "2", "31", "32", "33", "36"].contains(&c))
                })
        };
        text.lines().all(|line| {
            let mut opened = 0i32;
            let mut rest = line;
            while let Some(at) = rest.find('\u{1b}') {
                let after = &rest[at..];
                let Some(end) = after.find('m') else {
                    return false;
                };
                let seq = &after[..=end];
                if !own(seq) || seq.contains(']') {
                    return false;
                }
                opened += if seq == "\u{1b}[0m" { -1 } else { 1 };
                rest = &after[end + 1..];
            }
            opened == 0
        }) && !text.contains('\u{7}')
            && !text.contains('\u{202e}')
            && !text.contains("\u{1b}[31mRED")
            && !text.contains("\u{1b}]")
    }

    #[test]
    fn text_from_a_source_is_written_out_and_never_opens_or_closes_a_style() {
        // A name holding a style sequence, a title sequence and U+202E, given raw and as the
        // core gives it, escaped once already: on every screen it is written out, and every
        // escape byte is the program's own style, opened and closed on the same line.
        for odd in [ODD.to_string(), crate::known::whole(ODD)] {
            for screen in screens() {
                let all = texts(&screen, &odd).concat();
                assert!(styles_are_the_programs_own(&all), "{screen:?}\n{all:?}");
                // A terminal may break a long name between two of its characters; each hidden
                // one is written out whole all the same.
                let shown: &[&str] = if screen.terminal {
                    &[r"\u{1b}", r"\u{202e}", r"\u{7}"]
                } else {
                    &[r"\u{1b}[31m", r"\u{202e}", r"\u{1b}]0;owned\u{7}"]
                };
                for shown in shown {
                    assert!(all.contains(shown), "{screen:?}: {shown}\n{all}");
                }
            }
        }
        // Not vacuous: the program's own styles are there on a screen with colour.
        assert!(
            texts(&Screen::terminal(80, true), ODD)
                .concat()
                .contains("\u{1b}[1;31m")
        );
    }

    /// The labelled line about OSV data in the coverage view of `s`, unwrapped.
    fn osv_line(s: &v1::Status) -> String {
        let text = status(s, &Screen::pipe(), true);
        let line = text
            .lines()
            .find(|l| l.trim_start().starts_with("OSV data"))
            .unwrap_or_default()
            .to_string();
        let mut joined = line.clone();
        // The value may wrap; what follows the label line up to the next label is its value.
        for l in text.lines().skip_while(|l| *l != line).skip(1) {
            if !l.starts_with("    ") || l.trim().is_empty() {
                break;
            }
            joined.push(' ');
            joined.push_str(l.trim());
        }
        joined.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// `status_of` with these counts of projects and of known vulnerabilities.
    fn compared(known: u64, compared: u64, not_read: u64, no_lockfile: u64) -> v1::Status {
        let mut s = status_of("x");
        if let Some(v) = s.vulnerabilities.as_mut() {
            v.affected_records = known;
            v.unknown_packages = 0;
            v.projects_compared = compared;
            v.projects_not_read = not_read;
            v.projects_without_lockfile = no_lockfile;
        }
        s
    }

    #[test]
    fn with_no_project_compared_the_osv_line_says_so_by_count_and_gives_no_count_of_zero() {
        // No false calm: with none compared, a count of zero would read as "checked and fine".
        let said = osv_line(&compared(0, 0, 4, 12));
        assert!(
            said.contains("; no project's packages could be compared in full: the lockfiles of 4 projects were not all read, so whether a known vulnerability affects what was not read cannot be told, and 12 projects have no lockfile this version reads"),
            "{said}"
        );
        assert!(!said.contains("0 known vulnerabilit"), "{said}");
        // A count found in the packages read is still said.
        let found = osv_line(&compared(2, 0, 4, 0));
        assert!(
            found.contains("; 2 known vulnerabilities in the packages read"),
            "{found}"
        );
        // With no project held, only that is said; held projects that all three counts leave
        // out, such as those read against data not current, are not "none found".
        let mut none = compared(0, 0, 0, 0);
        none.estate.as_mut().unwrap().checkouts = 0;
        let said = osv_line(&none);
        assert!(
            said.contains("; no projects were found to compare. "),
            "{said}"
        );
        // A count that is not zero is said even when no project is held, never dropped.
        let mut left = compared(1, 0, 1, 0);
        left.estate.as_mut().unwrap().checkouts = 0;
        let said = osv_line(&left);
        assert!(
            !said.contains("no projects were found") && said.contains("1 known vulnerability"),
            "{said}"
        );
        // Nothing follows when no count gives a reason and nothing was read.
        let held = osv_line(&compared(0, 0, 0, 0));
        assert!(
            held.contains("; no project's packages could be compared in full. "),
            "{held}"
        );
    }

    #[test]
    fn with_some_projects_compared_the_osv_line_names_how_many_and_what_was_not() {
        let s = compared(0, 3, 4, 12);
        let said = osv_line(&s);
        assert!(
            said.contains(", 3 compared in full: 0 known vulnerabilities in the packages read; not compared: the lockfiles of 4 projects were not all read, so whether a known vulnerability affects what was not read cannot be told, and 12 projects have no lockfile this version reads"),
            "{said}"
        );
        // Either count alone is enough to leave projects not compared, and only it is said.
        let not_read = osv_line(&compared(0, 3, 4, 0));
        assert!(
            not_read.contains("; not compared: the lockfiles of 4 projects were not all read, so whether a known vulnerability affects what was not read cannot be told. "),
            "{not_read}"
        );
        let no_lockfile = osv_line(&compared(0, 3, 0, 12));
        assert!(
            no_lockfile
                .contains("; not compared: 12 projects have no lockfile this version reads. "),
            "{no_lockfile}"
        );
        // The headline is left alone.
        assert_eq!(
            status(&s, &Screen::pipe(), false).lines().next(),
            status(&compared(0, 3, 0, 0), &Screen::pipe(), false)
                .lines()
                .next()
        );
    }

    #[test]
    fn with_every_project_compared_the_osv_line_counts_in_packages_they_use() {
        let said = osv_line(&compared(0, 3, 0, 0));
        assert!(
            said.contains(", 3 compared in full: 0 known vulnerabilities in packages they use"),
            "{said}"
        );
        assert!(!said.contains("not compared"), "{said}");
    }

    #[test]
    fn a_package_that_cannot_be_told_leaves_the_projects_not_all_compared_and_is_the_reason() {
        // Never "packages they use" while a package cannot be told, and no "not compared:"
        // with nothing after it: the package is the reason, said by count, "it" for one.
        let mut s = compared(0, 3, 0, 0);
        s.vulnerabilities.as_mut().unwrap().unknown_packages = 1;
        let said = osv_line(&s);
        assert!(
            said.contains(", 3 compared in full: 0 known vulnerabilities in the packages read, and for 1 package whether one affects it cannot be told. "),
            "{said}"
        );
        let mut none = compared(0, 0, 0, 0);
        none.vulnerabilities.as_mut().unwrap().unknown_packages = 2;
        let said = osv_line(&none);
        assert!(
            said.contains(
                "; for 2 packages whether a known vulnerability affects them cannot be told. "
            ),
            "{said}"
        );
    }

    #[test]
    fn the_coverage_of_a_status_carries_every_part_the_status_used_to_say() {
        let text = status(&status_of("x"), &Screen::pipe(), true);
        for part in [
            "Store",
            "Last run",
            "Counted",
            "Estate",
            "Gaps",
            "Changes",
            "Set aside",
            "Watched places",
            "Installed software",
            "CISA catalogue",
            "OSV data",
            "This Mac",
            "Not fresh",
            "Watched",
            "Event level",
            "Needs a look",
            "Faults",
            "Limits of this version here",
            "Readings",
            "Machines not reached",
            "Readings that were not full",
            "No reader in this build for",
            "Latest changes in watched places, newest first, 50 of 1,234,567",
        ] {
            assert!(
                text.lines().any(|l| l.trim_start().starts_with(part)),
                "{part}\n{text}"
            );
        }
        // Each list whole, as the message holds it, and what it does not hold counted.
        assert!(text.contains("x/49"), "{text}");
        assert!(
            text.contains("2 more groups of readings not listed"),
            "{text}"
        );
        assert!(
            text.contains("1,234,566 more machines not listed"),
            "{text}"
        );
        // On a terminal too, every cause of what is not judged is there whole, broken into lines.
        let mut s = status_of("x");
        s.not_covered.push(v1::Uncovered {
            id: "not-understood".to_string(),
            who: "nothing".to_string(),
            class: v1::Cause::NoReader as i32,
            holds_on: v1::HoldsOn::ThisMac as i32,
            title: "Some files and packages are not understood by this version yet.".to_string(),
            examples_text: (0..5)
                .map(|i| format!("~/dev/project-{i}/poetry.lock"))
                .collect(),
            ..Default::default()
        });
        let narrow = status(&s, &Screen::terminal(80, false), true);
        let bare = |t: &str| t.split_whitespace().collect::<String>();
        let all = bare(&narrow);
        for u in s.not_covered.iter().filter(|u| u.who == "nothing") {
            assert!(
                all.contains(&bare(unstopped(&u.title))),
                "{}\n{narrow}",
                u.title
            );
            assert!(
                all.contains(&bare(&view::shown(&examples(u)))),
                "{}\n{narrow}",
                u.title
            );
        }
    }

    #[test]
    fn findings_are_grouped_under_their_level_most_severe_first_with_state_only_when_needed() {
        let f = findings_of("x");
        let text = findings(&f, false, &Screen::pipe());
        assert!(
            text.starts_with("✗ 60 open findings, 24 urgent: 7 critical, 33 high, 20 medium"),
            "{text}"
        );
        let heads: Vec<&str> = text
            .lines()
            .filter(|l| ["critical", "high", "medium", "low"].contains(l))
            .collect();
        assert_eq!(heads, ["critical", "high", "medium"], "{text}");
        assert!(
            !text.contains("  open  ") && !text.contains("f000000003c"),
            "{text}"
        );
        assert!(
            text.trim_end()
                .ends_with("→ immunity finding <id>   shows one and how to answer it"),
            "{text}"
        );
        let all = findings(&f, true, &Screen::pipe());
        assert!(
            all.starts_with("✗ 61 findings, 60 open, 24 urgent"),
            "{all}"
        );
        assert!(
            all.contains("  open  ") && all.contains("  seen  "),
            "{all}"
        );
        assert!(all.contains("\nlow\n"), "{all}");
    }

    #[test]
    fn a_package_finding_is_told_by_its_package_releases_and_project() {
        let text = findings(&findings_of("x"), false, &Screen::pipe());
        assert!(
            text.contains(
                r#""@ctrl/tinycolor-x" "4.1.1", "4.1.2" in "~/Developer/clients/northwind-traders/customer-portal-frontend-monorepo-with-a-very-long-name""#
            ),
            "{text}"
        );
        // On a terminal the package and its releases stay whole while the folder is cut.
        let cut = findings(&findings_of("x"), false, &Screen::terminal(120, false));
        assert!(
            cut.contains(r#""@ctrl/tinycolor-x" "4.1.1", "4.1.2" in "~/Dev"#),
            "{cut}"
        );
    }

    #[test]
    fn a_published_rule_is_named_by_its_own_title_cut_on_a_terminal_and_whole_in_a_pipe() {
        let f = findings_of("x");
        let title = "Osacompile Execution By Potentially Suspicious Process x";
        assert!(findings(&f, false, &Screen::pipe()).contains(title));
        let cut = findings(&f, false, &Screen::terminal(200, false));
        assert!(
            cut.contains(&format!("{}…", &title[..SHORT_MAX - 1])) && !cut.contains(title),
            "{cut}"
        );
    }

    #[test]
    fn a_findings_list_that_reaches_its_text_limit_says_how_many_it_shows() {
        let f = v1::Findings {
            latest_run_at: Some(1),
            findings: (1..=201)
                .map(|i| listed(i, v1::Level::Medium, false, format!("~/{i}")))
                .collect(),
            ..Default::default()
        };
        let text = findings(&f, false, &Screen::pipe());
        assert!(
            text.starts_with("✗ 201 open findings, none urgent"),
            "{text}"
        );
        assert!(
            text.contains("f00000000c8") && !text.contains("f00000000c9"),
            "{text}"
        );
        assert!(
            text.contains("Showing the first 200; 1 more not shown, 0 of them urgent."),
            "{text}"
        );
    }

    #[test]
    fn every_finding_as_text_puts_open_ones_first_and_its_cut_says_how_many_hidden_are_urgent() {
        // The answer's order is urgent first across states: closed urgent findings come before
        // open ones that are not urgent. Open ones are shown first all the same.
        let found = |i: usize, state: v1::FindingState, urgent: bool| {
            let mut l = listed(i, v1::Level::High, urgent, format!("~/{i}"));
            if let Some(r) = l.finding.as_mut() {
                r.state = state as i32;
            }
            l
        };
        let closed = (0..150).map(|i| found(i, v1::FindingState::Expected, true));
        let open = (150..300).map(|i| found(i, v1::FindingState::Open, false));
        let f = v1::Findings {
            latest_run_at: Some(1),
            findings: closed.chain(open).collect(),
            ..Default::default()
        };
        let text = findings(&f, true, &Screen::pipe());
        assert!(
            text.starts_with("✗ 300 findings, 150 open, none urgent"),
            "{text}"
        );
        // All 150 open ones, then the first 50 closed ones; 100 closed urgent ones are hidden.
        assert!(
            text.contains("f000000012b") && text.contains("f0000000031"),
            "{text}"
        );
        assert!(!text.contains("f0000000032"), "{text}");
        assert!(
            text.contains("Showing the first 200; 100 more not shown, 100 of them urgent."),
            "{text}"
        );
    }

    #[test]
    fn findings_of_one_rule_are_listed_under_its_name_said_once_urgent_groups_first() {
        let of = |i: usize, rule: &str, short: &str, urgent: bool| {
            let mut l = listed(i, v1::Level::High, urgent, format!("~/dev/p{i}/x"));
            if let Some(r) = l.finding.as_mut() {
                r.rule = Some(rule.to_string());
            }
            l.short_title = short.to_string();
            l
        };
        let f = v1::Findings {
            latest_run_at: Some(CHECKED),
            answered_at: NOW,
            findings: vec![
                of(1, "a", "Three that are not urgent", false),
                of(2, "c", "Two that are not urgent", false),
                of(3, "a", "Three that are not urgent", false),
                of(4, "b", "One that is urgent", true),
                of(5, "a", "Three that are not urgent", false),
                of(6, "c", "Two that are not urgent", false),
            ],
            ..Default::default()
        };
        for screen in [Screen::pipe(), Screen::terminal(80, false)] {
            let text = findings(&f, false, &screen);
            let titles: Vec<&str> = text
                .lines()
                .filter(|l| l.starts_with("  ") && !l.starts_with("    "))
                .collect();
            assert_eq!(
                titles,
                [
                    "  One that is urgent   1",
                    "  Three that are not urgent   3",
                    "  Two that are not urgent   2"
                ],
                "{text}"
            );
            // Each title once; under it, its findings only, with no title on their rows.
            for short in ["One that is urgent", "Three that are not urgent"] {
                assert_eq!(text.matches(short).count(), 1, "{text}");
            }
            let rows: Vec<&str> = text.lines().filter(|l| l.starts_with("    f")).collect();
            assert_eq!(rows.len(), 6, "{text}");
            assert!(
                rows[0].starts_with("    f0000000004  \"~/dev/p4/x") && rows[0].ends_with("urgent"),
                "{text}"
            );
            assert!(rows[1].contains("f0000000001") && rows[3].contains("f0000000005"));
        }
        // The room the title took is the place's: a long path keeps more of itself at 80.
        let long = v1::Findings {
            latest_run_at: Some(CHECKED),
            findings: vec![listed(
                1,
                v1::Level::High,
                false,
                format!("{LONG}/package-lock.json"),
            )],
            ..Default::default()
        };
        let text = findings(&long, false, &Screen::terminal(80, false));
        let row = text.lines().find(|l| l.starts_with("    f")).unwrap();
        assert!(screen::columns(row) >= 70, "{text}");
    }

    /// A new hook of a group in `folder`, as the core lists it.
    fn hook(
        i: usize,
        group: Option<&str>,
        folder: Option<&str>,
        urgent: bool,
    ) -> v1::ListedFinding {
        v1::ListedFinding {
            group: group.map(str::to_string),
            folder_text: folder.map(str::to_string),
            change: Some(v1::Change::New as i32),
            ..listed(
                i,
                v1::Level::Medium,
                urgent,
                format!("~/dev/shop/.git/hooks/h{i}"),
            )
        }
    }

    fn list_of(findings: Vec<v1::ListedFinding>) -> v1::Findings {
        v1::Findings {
            answered_at: NOW,
            latest_run_at: Some(CHECKED),
            findings,
            ..Default::default()
        }
    }

    /// The lines of a text that hold `id`.
    fn holding<'a>(text: &'a str, id: &str) -> Vec<&'a str> {
        text.lines().filter(|l| l.contains(id)).collect()
    }

    #[test]
    fn a_folded_line_counts_the_findings_it_names_and_names_each_by_its_whole_id() {
        let folder = Some("~/dev/shop/.git/hooks");
        let mut list: Vec<v1::ListedFinding> = (0..14)
            .map(|i| hook(i, Some("g1"), folder, false))
            .collect();
        // A group of one is an ordinary row.
        list.push(hook(20, Some("g2"), Some("~/dev/cart/.git/hooks"), false));
        let f = list_of(list);
        for screen in screens() {
            let text = visible(&findings(&f, false, &screen));
            // The heading counts findings, and says the lines too.
            assert!(
                text.contains("Script git runs by itself changed   15 findings in 2 lines"),
                "{text}"
            );
            // Every id whole, once; the folded line says how many, and no more nor fewer.
            for l in &f.findings {
                let id = &l.finding.as_ref().unwrap().id;
                assert_eq!(text.matches(id.as_str()).count(), 1, "{id}\n{text}");
            }
            // The folder ends its line, as a path does; the ids are on the lines under it and
            // nothing else is, one line in a pipe.
            let lines: Vec<&str> = text.lines().collect();
            let k = lines
                .iter()
                .position(|l| *l == "    14 findings  added  ~/dev/shop/.git/hooks")
                .unwrap_or_else(|| panic!("{text}"));
            let under: Vec<&str> = lines[k + 1..]
                .iter()
                .take_while(|l| l.starts_with("      f"))
                .copied()
                .collect();
            let named: Vec<&str> = under
                .iter()
                .flat_map(|l| l.split([',', ' ']))
                .filter(|s| !s.is_empty())
                .collect();
            let ids: Vec<String> = (0..14).map(|i| format!("f{i:010x}")).collect();
            assert_eq!(named, ids, "{text}");
            if !screen.terminal {
                assert_eq!(under.len(), 1, "{text}");
            }
            // The group of one: its own id first on its row, with its own place.
            assert!(
                holding(&text, "f0000000014")[0]
                    .starts_with("    f0000000014  added  \"~/dev/shop/.git/hooks/h20"),
                "{text}"
            );
            // Nothing on it answers.
            assert!(!text.contains("--with"), "{text}");
        }
    }

    #[test]
    fn findings_fold_only_by_a_group_key_present_and_equal_and_never_across_urgency_or_state() {
        let folder = Some("~/dev/shop/.git/hooks");
        let mut seen = hook(7, Some("g1"), folder, false);
        if let Some(r) = seen.finding.as_mut() {
            r.state = v1::FindingState::Seen as i32;
        }
        // With the response layer's verdicts, counted, or naming its own finding about it.
        let judged = |i: usize, verdicts: v1::Verdicts| v1::ListedFinding {
            verdicts: Some(verdicts),
            ..hook(i, Some("g1"), folder, false)
        };
        let f = list_of(vec![
            hook(0, Some("g1"), folder, false),
            hook(1, Some("g1"), folder, true),
            hook(2, Some("g1"), folder, false),
            hook(3, Some("g1"), folder, true),
            // The same folder, no key; a key with no folder.
            hook(4, None, folder, false),
            hook(5, None, folder, false),
            hook(6, Some("g3"), None, false),
            hook(8, Some("g3"), None, false),
            seen,
            hook(9, Some("g1"), folder, false),
            judged(
                10,
                v1::Verdicts {
                    total: 1,
                    ..Default::default()
                },
            ),
            judged(
                11,
                v1::Verdicts {
                    verdict_finding: Some(v1::FindingRef::default()),
                    ..Default::default()
                },
            ),
        ]);
        for screen in [Screen::pipe(), Screen::terminal(80, false)] {
            let text = findings(&f, true, &screen);
            // The urgent two apart from the others, on a line that says it.
            let urgent = holding(&text, "f0000000001");
            assert_eq!(urgent, holding(&text, "f0000000003"), "{text}");
            let other = holding(&text, "f0000000000");
            assert_eq!(other, holding(&text, "f0000000009"), "{text}");
            assert_ne!(urgent, other, "{text}");
            // The folded line an id is named under.
            let line = |id: &str| {
                let at = text.find(id).unwrap();
                let head = text[..at].rfind("findings").unwrap();
                text[text[..head].rfind('\n').unwrap()..]
                    .lines()
                    .nth(1)
                    .unwrap()
            };
            assert!(line("f0000000001").contains("2 findings"), "{text}");
            assert!(line("f0000000001").contains("urgent"), "{text}");
            assert!(line("f0000000000").contains("3 findings"), "{text}");
            assert!(!line("f0000000000").contains("urgent"), "{text}");
            // The answered one of the group apart from the open ones.
            let row = |id: &str| holding(&text, id)[0].starts_with(&format!("    {id}  "));
            assert!(row("f0000000007"), "{text}");
            // Without a key, without a folder to say, or with a verdict, each its own row.
            for id in [
                "f0000000004",
                "f0000000005",
                "f0000000006",
                "f0000000008",
                "f000000000a",
                "f000000000b",
            ] {
                assert!(row(id), "{text}");
            }
        }
    }

    #[test]
    fn the_coverage_of_a_status_lists_what_is_watched_as_a_table() {
        let mut s = status_of("x");
        if let Some(m) = s.this_mac.as_mut() {
            m.watched.push(v1::WatchedThing {
                what: "program starts".to_string(),
                count: 35,
                how: "events".to_string(),
            });
        }
        let text = status(&s, &Screen::pipe(), true);
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|l| *l == "  Watched")
            .unwrap_or_else(|| panic!("{text}"));
        let words = |l: &str| l.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(words(lines[at + 1]), "Place How many How often", "{text}");
        assert_eq!(
            words(lines[at + 2]),
            "startup items 1,234,567 hourly",
            "{text}"
        );
        assert_eq!(words(lines[at + 3]), "program starts 35 events", "{text}");
        // The counts stand to the right, in one column.
        assert_eq!(
            lines[at + 2]
                .find("1,234,567")
                .map(|i| i + "1,234,567".len()),
            lines[at + 3].find("35").map(|i| i + 2),
            "{text}"
        );
        assert!(
            !text.contains("startup items: 1,234,567 (hourly)"),
            "{text}"
        );
    }

    /// A status with nothing found, after a fresh check, on a Mac watched whole by a live
    /// watcher, nothing failed and every download current: the one the green headline is for.
    fn calm_status() -> v1::Status {
        let mut s = status_of("x");
        s.needs_a_look = Some(v1::NeedsALook::default());
        s.last_run = None;
        s.watching = Some(v1::Watcher::default());
        s.event_level = None;
        s.not_covered.clear();
        if let Some(m) = s.this_mac.as_mut() {
            m.fresh = true;
            m.live = true;
            m.state = v1::ThisMacState::Watched as i32;
        }
        if let Some(t) = s.threats.as_mut() {
            t.outcome = v1::FeedOutcome::Unchanged as i32;
        }
        if let Some(c) = s.coverage.as_mut() {
            c.failed = 0;
            c.unreached_total = 0;
            c.unreached.clear();
        }
        s
    }

    /// The fault lines of a text, as a terminal shows them, each with the lines it goes on to.
    fn fault_lines_of(text: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for l in text.lines().map(visible) {
            if l.starts_with("  ! ") {
                out.push(l.trim().to_string());
            } else if l.starts_with("    ")
                && let Some(last) = out.last_mut()
            {
                last.push(' ');
                last.push_str(l.trim());
            }
        }
        out
    }

    /// The fault lines of the default status of `s` in a pipe.
    fn faults_in(s: &v1::Status) -> Vec<String> {
        fault_lines_of(&status(s, &Screen::pipe(), false))
    }

    #[test]
    fn a_calm_status_is_the_headline_and_how_this_mac_is_watched_and_nothing_else() {
        let mut s = calm_status();
        s.estate.as_mut().unwrap().checkouts = 46;
        let text = status(&s, &Screen::terminal(80, false), false);
        assert_eq!(
            text,
            "✓ Nothing needs a look                                         checked 3 min ago\n  Watching live · this Mac and 46 projects\n"
        );
        // A store that knows no project says this Mac alone.
        s.estate = None;
        assert_eq!(
            status(&s, &Screen::pipe(), false),
            format!(
                "✓ Nothing needs a look   checked {}\n  Watching live · this Mac\n",
                view::utc(CHECKED)
            )
        );
    }

    #[test]
    fn a_limit_of_this_version_leaves_the_default_text_and_the_headline_calm() {
        // Every cause of a class other than failed, as the core gives it, with the counts of
        // what was read and not read, bundles that do not verify and kinds no reader reads.
        let mut s = calm_status();
        for cause in crate::covered::CAUSES
            .iter()
            .filter(|c| c.class != crate::store::Cause::Failed)
        {
            s.not_covered.push(v1::Uncovered {
                advice: "Do something.".to_string(),
                ..uncovered(
                    cause.id,
                    cause.who,
                    false,
                    &format!("What the cause {} says.", cause.id),
                    &[("example-limit", None)],
                )
            });
        }
        if let Some(c) = s.coverage.as_mut() {
            (c.no_reader, c.not_given) = (9, 7);
        }
        s.integrity.as_mut().unwrap().bundles_not_verifying = 4;
        s.event_level = Some(v1::EventLevel {
            state: v1::CollectorState::NotInstalled as i32,
            ..Default::default()
        });
        let calm = calm_status();
        for screen in screens() {
            assert_eq!(status(&s, &screen, false), status(&calm, &screen, false));
        }
        assert!(
            status(&s, &Screen::pipe(), false).starts_with("✓ Nothing needs a look"),
            "{}",
            status(&s, &Screen::pipe(), false)
        );
        // `--coverage` keeps each of them, under the limits.
        let whole = status(&s, &Screen::pipe(), true);
        assert!(whole.contains("  Limits of this version here\n"), "{whole}");
        assert!(
            whole.contains("What the cause not-understood says"),
            "{whole}"
        );
    }

    #[test]
    fn a_check_that_died_is_a_fault_line_with_the_command_that_runs_one() {
        let mut s = calm_status();
        s.last_run = Some(v1::CheckMark {
            id: "run-3".to_string(),
            started_at: NOW - 600,
            finished_at: None,
        });
        let said = format!(
            "! The check started {} did not finish   immunity run",
            view::utc(NOW - 600)
        );
        assert_eq!(faults_in(&s), [said]);
        assert!(status(&s, &Screen::pipe(), false).starts_with("✓ Nothing needs a look"));
        // While it runs, it has not died: the headline says it is checking now.
        s.running = true;
        assert!(faults_in(&s).is_empty());
        assert!(
            status(&s, &Screen::terminal(80, false), false)
                .lines()
                .next()
                .unwrap()
                .ends_with("checked 3 min ago · checking now"),
        );
    }

    #[test]
    fn a_status_that_is_not_fresh_says_since_when_and_why_and_is_never_calm() {
        let mut s = calm_status();
        let m = s.this_mac.as_mut().unwrap();
        (m.fresh, m.checked_at) = (false, Some(NOW - 3 * 3600));
        m.stale_reason = Some("the latest full check finished more than 2 hours ago".to_string());
        let text = status(&s, &Screen::terminal(80, false), false);
        assert_eq!(
            text,
            "? Not checked for 3 h\n  The latest full check finished more than 2 hours ago              immunity run\n"
        );
        // With no watcher, the watcher is the reason, said once.
        s.watching = None;
        s.this_mac.as_mut().unwrap().live = false;
        let text = status(&s, &Screen::terminal(80, false), false);
        assert_eq!(
            text,
            "? Not checked for 3 h\n  No watcher runs: changes are seen only at a check you run          immunity on\n"
        );
        assert!(!text.contains('✓'));
        // Yellow on a screen with colour.
        assert!(
            status(&s, &Screen::terminal(80, true), false).starts_with("\u{1b}[1;33m? Not checked")
        );
    }

    #[test]
    fn a_watcher_that_does_not_watch_live_is_a_fault_line_with_the_command_that_starts_one() {
        let on = "immunity on";
        let not_running = |change: fn(&mut v1::Status)| {
            let mut s = calm_status();
            s.watching = None;
            s.this_mac.as_mut().unwrap().live = false;
            change(&mut s);
            faults_in(&s)
        };
        assert_eq!(
            not_running(|_| {}),
            [format!(
                "! No watcher runs: changes are seen only at a check you run   {on}"
            )]
        );
        assert_eq!(
            not_running(|s| s.login_job_installed = Some(true)),
            [format!(
                "! The watcher is not running: its login job is in place   {on}"
            )]
        );
        assert_eq!(
            not_running(|s| s.watcher_restarting_since_at = Some(NOW - 5)),
            ["! The watcher is restarting on a new core"]
        );
        // Gone after `immunity on`, by something other than `immunity off`.
        assert_eq!(
            not_running(|s| {
                (s.turned_on_at, s.turned_on_latest) = (Some(NOW - 60), Some(true));
                s.login_job_installed = Some(false);
            }),
            [format!(
                "! Immunity Core is off: its job, turned on {}, is gone, and immunity off did not turn it off   {on}",
                view::utc(NOW - 60)
            )]
        );
        // A watcher that holds the store and has not read yet.
        let mut s = calm_status();
        s.this_mac.as_mut().unwrap().live = false;
        assert_eq!(
            faults_in(&s),
            ["! A watcher runs and has not completed its first reading"]
        );
        // Live, as the message says, but no watcher holds the store: not live.
        let mut s = calm_status();
        s.watching = None;
        assert_eq!(faults_in(&s).len(), 1, "{:?}", faults_in(&s));
        // None of them leaves the headline green, and the line is never dim.
        let screen = Screen::terminal(100, true);
        let text = status(&s, &screen, false);
        assert!(text.contains("\u{1b}[33m!\u{1b}[0m"), "{text:?}");
        assert!(!text.contains("\u{1b}[2m!"), "{text:?}");
    }

    #[test]
    fn each_failure_of_the_watcher_is_a_fault_line_with_when_and_what_it_said() {
        let mut s = calm_status();
        s.this_mac.as_mut().unwrap().live = false;
        s.watching.as_mut().unwrap().failed = vec![
            v1::WatcherFailure {
                what: crate::watch::FULL_CHECK.to_string(),
                at: NOW - 3600,
                detail_text: "the store was busy".to_string(),
            },
            v1::WatcherFailure {
                what: crate::watch::READ.to_string(),
                at: NOW - 120,
                detail_text: format!("could not be read: {LONG}"),
            },
        ];
        assert_eq!(
            faults_in(&s),
            [
                format!(
                    "! The watcher's latest full check failed {}: \"the store was busy\"   immunity run",
                    view::utc(NOW - 3600)
                ),
                format!(
                    "! The watcher's latest reading of the watched places failed {}: \"could not be read: {LONG}\"",
                    view::utc(NOW - 120)
                ),
            ]
        );
        // On a terminal what the source said is cut to a line, from its start, and the time is
        // how long ago.
        let text = status(&s, &Screen::terminal(80, false), false);
        let lines = fault_lines_of(&text);
        assert!(
            lines[0].starts_with(
                "! The watcher's latest full check failed 1 h ago: \"the store was busy\""
            ) && lines[0].ends_with("immunity run"),
            "{text}"
        );
        assert!(lines[1].ends_with("…\"") && !text.contains(LONG), "{text}");
    }

    #[test]
    fn immunity_off_is_the_off_form_and_never_calm() {
        let mut s = calm_status();
        s.watching = None;
        s.this_mac.as_mut().unwrap().live = false;
        (s.turned_off_at, s.turned_on_latest) = (Some(NOW - 7200), Some(false));
        s.login_job_installed = Some(false);
        let text = status(&s, &Screen::terminal(80, false), false);
        assert_eq!(
            text,
            "○ Immunity Core is off                                        turned off 2 h ago\n  Nothing is watched or checked until it is turned on                immunity on\n"
        );
        // Not fresh as well: still the off form, since being off is why.
        s.this_mac.as_mut().unwrap().fresh = false;
        assert!(status(&s, &Screen::pipe(), false).starts_with("○ Immunity Core is off"));
        // With something to look at, the finding leads and being off is a fault line.
        s.this_mac.as_mut().unwrap().fresh = true;
        s.needs_a_look = Some(v1::NeedsALook {
            total: 1,
            by_rule: vec![group("watched.git-hook", v1::Level::Medium, 1, 0)],
            ..Default::default()
        });
        let text = status(&s, &Screen::pipe(), false);
        assert!(text.starts_with("● 1 thing needs a look"), "{text}");
        assert_eq!(
            fault_lines_of(&text),
            [format!(
                "! Immunity Core is off: turned off {} with immunity off   immunity on",
                view::utc(NOW - 7200)
            )]
        );
    }

    #[test]
    fn off_never_hides_a_finding_or_a_check_that_runs() {
        let mut s = calm_status();
        s.watching = None;
        s.this_mac.as_mut().unwrap().live = false;
        (s.turned_off_at, s.turned_on_latest) = (Some(NOW - 7200), Some(false));
        s.login_job_installed = Some(false);
        let off = format!(
            "! Immunity Core is off: turned off {} with immunity off   immunity on",
            view::utc(NOW - 7200)
        );
        // A check running after one finished: what was found leads, checking now, and off is a
        // fault line.
        s.running = true;
        s.last_run = Some(v1::CheckMark {
            id: "run-2".to_string(),
            started_at: NOW - 60,
            ..Default::default()
        });
        let text = status(&s, &Screen::pipe(), false);
        assert!(
            text.starts_with("✓ Nothing needs a look   checked ")
                && text.lines().next().unwrap().ends_with(" · checking now"),
            "{text}"
        );
        assert_eq!(fault_lines_of(&text), std::slice::from_ref(&off));
        // The first check running: its own form, and off a fault line.
        s.this_mac.as_mut().unwrap().checked_at = None;
        let text = status(&s, &Screen::pipe(), false);
        assert!(text.starts_with("… The first check is running"), "{text}");
        assert!(fault_lines_of(&text).contains(&off), "{text}");
    }

    #[test]
    fn the_terminal_says_the_watchers_one_case_and_a_restart_only_while_no_watcher_holds_the_store()
    {
        // Live, with a watcher on the store, and a restart's time, which one reading never gives
        // together: the watcher on the store is the case (`watch::case`), as on the pages.
        let mut s = calm_status();
        s.watcher_restarting_since_at = Some(NOW - 30);
        let text = super::status(&s, &Screen::pipe(), false);
        assert!(fault_lines_of(&text).is_empty(), "{text}");
        // With none on the store, the restart is the case.
        s.this_mac.as_mut().unwrap().live = false;
        s.watching = None;
        let text = super::status(&s, &Screen::pipe(), false);
        assert_eq!(
            fault_lines_of(&text),
            ["! The watcher is restarting on a new core"],
            "{text}"
        );
    }

    #[test]
    fn nothing_to_look_at_is_said_only_of_a_fresh_answer_that_looked_whatever_the_headline() {
        // The message says calm; its own fields do not hold it up.
        let mut s = calm_status();
        s.headline = v1::Headline::Calm as i32;
        let text = |s: &v1::Status| super::status(s, &Screen::pipe(), false);
        assert!(text(&s).starts_with("✓ Nothing needs a look"));
        s.this_mac.as_mut().unwrap().fresh = false;
        assert!(text(&s).starts_with("? Not checked since "), "{}", text(&s));
        s.this_mac.as_mut().unwrap().checked_at = None;
        assert!(
            text(&s).starts_with("? No check has finished yet"),
            "{}",
            text(&s)
        );
        s.needs_a_look = None;
        assert!(
            text(&s).starts_with("? No run of this build has looked for findings yet"),
            "{}",
            text(&s)
        );
        // No this Mac in the message: no finished check is known.
        let mut s = calm_status();
        s.headline = v1::Headline::InPart as i32;
        s.this_mac = None;
        assert!(
            text(&s).starts_with("? No check has finished yet"),
            "{}",
            text(&s)
        );
    }

    #[test]
    fn an_answer_that_is_not_fresh_is_said_beside_a_finding_with_why_and_the_command_that_fits() {
        let mut s = calm_status();
        s.needs_a_look = Some(v1::NeedsALook {
            total: 1,
            by_rule: vec![group("watched.git-hook", v1::Level::Medium, 1, 0)],
            ..Default::default()
        });
        let m = s.this_mac.as_mut().unwrap();
        m.fresh = false;
        m.stale_reason = Some("the latest full check finished more than 2 hours ago".to_string());
        let text = status(&s, &Screen::pipe(), false);
        assert!(text.starts_with("● 1 thing needs a look"), "{text}");
        assert_eq!(
            fault_lines_of(&text)[0],
            "! This answer is not fresh: the latest full check finished more than 2 hours ago   immunity run"
        );
        // No watcher runs: the command that starts one.
        s.watching = None;
        s.this_mac.as_mut().unwrap().live = false;
        let text = status(&s, &Screen::pipe(), false);
        assert!(
            fault_lines_of(&text)[0].starts_with("! This answer is not fresh: ")
                && fault_lines_of(&text)[0].ends_with("   immunity on"),
            "{text}"
        );
    }

    #[test]
    fn in_part_never_shows_a_bare_check_mark_unless_only_a_limit_the_design_accepts_holds_it() {
        let line = ["! Something was not read in full   immunity status --coverage"];
        let pipe = |s: &v1::Status| super::status(s, &Screen::pipe(), false);
        // This Mac watched in part with nothing else to say it.
        let mut in_part = calm_status();
        in_part.this_mac.as_mut().unwrap().state = v1::ThisMacState::WatchedInPart as i32;
        let s = crate::headline::headed(in_part);
        assert_eq!(s.headline, v1::Headline::InPart as i32);
        assert!(pipe(&s).starts_with("✓ Nothing needs a look"));
        assert_eq!(fault_lines_of(&pipe(&s)), line, "{}", pipe(&s));
        // A reason, or a state of this Mac, this build does not know.
        let mut s = calm_status();
        s.headline = v1::Headline::InPart as i32;
        s.headline_because = vec![99];
        assert_eq!(fault_lines_of(&pipe(&s)), line);
        s.headline_because = vec![v1::HeadlineBecause::ThisMac as i32];
        s.this_mac.as_mut().unwrap().state = 99;
        assert_eq!(fault_lines_of(&pipe(&s)), line);
        // Readings counted as failed and machines not reached with no fault that names them, as
        // the core heads it: in part, and the one line.
        let mut s = calm_status();
        let c = s.coverage.as_mut().unwrap();
        (c.failed, c.unreached_total) = (3, 2);
        let s = crate::headline::headed(s);
        assert_eq!(s.headline, v1::Headline::InPart as i32);
        assert_eq!(fault_lines_of(&pipe(&s)), line, "{}", pipe(&s));
        // Deleted unread as well as by the cap: said as its own fault, not as unexplained.
        let mut s = calm_status();
        s.headline = v1::Headline::InPart as i32;
        s.headline_because = vec![v1::HeadlineBecause::ThisMac as i32];
        let span = Some(v1::Span {
            since_check: 1,
            last_day: 1,
        });
        s.event_level = Some(v1::EventLevel {
            state: v1::CollectorState::Running as i32,
            files_removed_by_cap: span,
            files_removed_unread: span,
            ..Default::default()
        });
        assert_eq!(
            fault_lines_of(&pipe(&s)),
            [
                "! 1 file of the event log was deleted before it was read since the latest check   immunity run"
            ]
        );
    }

    #[test]
    fn an_answer_in_part_with_no_fault_line_says_something_was_not_read_in_full_and_a_fault_says_itself()
     {
        // No limit holds an answer in part, so every reason with no line of its own, a reason
        // this build does not know among them, is said by the one line; a fault says itself.
        use v1::HeadlineBecause as B;
        let line =
            vec!["! Something was not read in full   immunity status --coverage".to_string()];
        let status = |because: &[i32]| {
            let mut s = calm_status();
            s.headline = v1::Headline::InPart as i32;
            s.headline_because = because.to_vec();
            s
        };
        let (m, w) = (B::ThisMac as i32, B::Watcher as i32);
        for (case, s) in [
            ("this Mac", status(&[m])),
            ("a reason repeated", status(&[m, m])),
            ("an unknown reason", status(&[m, 99])),
            ("another reason", status(&[m, w])),
            ("no reason", status(&[])),
        ] {
            let text = super::status(&s, &Screen::pipe(), false);
            assert!(text.starts_with("✓ Nothing needs a look"), "{case}\n{text}");
            assert_eq!(fault_lines_of(&text), line, "{case}\n{text}");
        }
        let mut s = status(&[m, B::NotCovered as i32]);
        s.not_covered.push(v1::Uncovered {
            scope: "this_mac".to_string(),
            ..uncovered(
                "could-not-read",
                "nothing",
                false,
                "1 thing could not be read.",
                &[("~/a", None)],
            )
        });
        assert_eq!(
            fault_lines_of(&super::status(&s, &Screen::pipe(), false)),
            [r#"! Could not read: "~/a""#]
        );
    }

    #[test]
    fn a_finding_is_a_finding_however_the_message_counts_it() {
        let mut one = listed(3, v1::Level::Medium, false, "~/dev/site".to_string());
        if let Some(r) = one.finding.as_mut() {
            r.rule = Some("watched.git-hook".to_string());
        }
        let items = v1::NeedsALook {
            items: vec![v1::LookFinding {
                finding: Some(one),
                ..Default::default()
            }],
            ..Default::default()
        };
        let rules = v1::NeedsALook {
            by_rule: vec![group("watched.git-hook", v1::Level::Medium, 1, 0)],
            ..Default::default()
        };
        // Counted as none, but listed by item or by rule, in a message that says calm.
        for (case, n) in [("an item", items), ("a rule", rules)] {
            let mut s = calm_status();
            s.headline = v1::Headline::Calm as i32;
            s.needs_a_look = Some(n);
            let text = super::status(&s, &Screen::pipe(), false);
            assert!(text.starts_with("● 1 thing needs a look"), "{case}\n{text}");
            assert!(!text.contains('✓'), "{case}\n{text}");
            // The run says the same, so what it first saw never follows a ✓.
            let ran = crate::after_run::run(&s, &Screen::pipe());
            assert!(ran.starts_with("● 1 thing needs a look"), "{case}\n{ran}");
        }
    }

    #[test]
    fn a_cause_that_names_what_failed_without_reasons_still_names_it() {
        let mut s = calm_status();
        s.not_covered.push(v1::Uncovered {
            scope: "servers".to_string(),
            count: 3,
            ..uncovered(
                "servers-not-checked",
                "you",
                false,
                "3 of your servers were not checked last time.",
                &[("staging-api", None), ("db-2", None)],
            )
        });
        assert_eq!(
            faults_in(&s),
            [
                "! 3 of your servers were not checked last time: \"staging-api\"; \"db-2\", and 1 more"
            ]
        );
    }

    #[test]
    fn an_event_level_that_records_nothing_is_a_fault_line_said_once() {
        let level = |state: v1::CollectorState, words: &str| v1::EventLevel {
            state: state as i32,
            said_text: Some("eslogger: Not permitted".to_string()),
            in_words: Some(v1::EventLevelWords {
                state: words.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        for (state, words) in [
            (v1::CollectorState::Refused, "refused by macOS"),
            (v1::CollectorState::Failing, "stopped by an error"),
            (v1::CollectorState::Silent, "silent"),
            (v1::CollectorState::Failed, "cannot be read"),
            (v1::CollectorState::Unspecified, ""),
        ] {
            let mut s = calm_status();
            s.event_level = Some(level(state, words));
            let words = if words.is_empty() {
                "not running"
            } else {
                words
            };
            assert_eq!(
                faults_in(&s),
                [format!(
                    "! Program starts are not seen; event level: {words}: \"eslogger: Not permitted\""
                )]
            );
        }
        // As the core gives it, with its cause: the cause's words and advice, and the level's
        // own line is not said again.
        let mut s = calm_status();
        s.event_level = Some(level(v1::CollectorState::Refused, "refused by macOS"));
        s.not_covered.push(v1::Uncovered {
            advice: "Open System Settings and turn on eslogger.".to_string(),
            value_text: Some("eslogger: Not permitted".to_string()),
            ..uncovered(
                "eslogger-refused",
                "you",
                false,
                "Program starts are not seen: macOS refuses eslogger Full Disk Access.",
                &[],
            )
        });
        assert_eq!(
            faults_in(&s),
            [
                r#"! Program starts are not seen: macOS refuses eslogger Full Disk Access: "eslogger: Not permitted" Open System Settings and turn on eslogger."#
            ]
        );
        // Not installed is a limit and says nothing.
        let mut s = calm_status();
        s.event_level = Some(level(v1::CollectorState::NotInstalled, "not installed"));
        assert!(faults_in(&s).is_empty());
    }

    #[test]
    fn what_the_event_level_lost_since_the_latest_check_is_a_fault_line_each() {
        let span = |since_check: u64, last_day: u64| {
            Some(v1::Span {
                since_check,
                last_day,
            })
        };
        let running = v1::EventLevel {
            state: v1::CollectorState::Running as i32,
            ..Default::default()
        };
        let mut s = calm_status();
        s.event_level = Some(v1::EventLevel {
            lost: span(3, 9),
            unknown_losses: span(1, 4),
            unreadable_lines: span(1_234_567, 1_234_567),
            files_removed_unread: span(2, 2),
            files_removed_by_cap: span(5, 5),
            file_events: Some(v1::FileEvents {
                collected: true,
                lost: span(4, 4),
                unreadable_events: span(1, 1),
                unknown_losses: span(2, 2),
                ..Default::default()
            }),
            ..running.clone()
        });
        let run = "   immunity run";
        assert_eq!(
            faults_in(&s),
            [
                format!("! 3 program starts were missed since the latest check{run}"),
                format!(
                    "! The collector restarted once since the latest check, and program starts in those moments were not seen{run}"
                ),
                format!(
                    "! 1,234,567 lines of the event log could not be read since the latest check{run}"
                ),
                format!(
                    "! 2 files of the event log were deleted before they were read since the latest check{run}"
                ),
                format!("! 5 file events were missed since the latest check{run}"),
                format!(
                    "! The numbering of file events started again twice since the latest check{run}"
                ),
            ]
        );
        // Losses of the last day that a finished check has covered, a line that could not be
        // read among them, files the cap deleted once they were read, and file events not
        // collected say nothing.
        s.event_level = Some(v1::EventLevel {
            lost: span(0, 9),
            unreadable_lines: span(0, 1),
            files_removed_by_cap: span(5, 5),
            file_events: Some(v1::FileEvents {
                collected: false,
                lost: span(4, 4),
                ..Default::default()
            }),
            ..running
        });
        assert!(faults_in(&s).is_empty(), "{:?}", faults_in(&s));
        // The same line read since the latest check is said, with what ends it.
        if let Some(l) = s.event_level.as_mut() {
            l.unreadable_lines = span(1, 1);
        }
        assert_eq!(
            faults_in(&s),
            [format!(
                "! 1 line of the event log could not be read since the latest check{run}"
            )]
        );
    }

    #[test]
    fn every_cause_with_fault_is_a_fault_line_whoever_can_fix_it_and_a_limit_never_is() {
        let screen = Screen::terminal(400, true);
        // Every cause the core can raise, alone in that status, a fault and a limit, whatever its
        // class, and a class this build does not know, or none.
        let later = |class| v1::Uncovered {
            id: "a-cause-of-a-later-core".to_string(),
            who: "nothing".to_string(),
            class,
            title: "What the cause a-cause-of-a-later-core says.".to_string(),
            ..Default::default()
        };
        let causes = crate::covered::CAUSES.iter().map(|cause| v1::Uncovered {
            scope: cause.scope.to_string(),
            ..uncovered(
                cause.id,
                cause.who,
                false,
                &format!("What the cause {} says.", cause.id),
                &[],
            )
        });
        for u in causes.chain([later(0), later(99)]) {
            for fault in [true, false] {
                let mut s = calm_status();
                s.not_covered.push(v1::Uncovered { fault, ..u.clone() });
                let faults = faults_in(&s);
                match fault {
                    true => assert_eq!(faults, [format!("! {}", unstopped(&u.title))], "{}", u.id),
                    false => assert!(faults.is_empty(), "{}: {faults:?}", u.id),
                }
                // The headline stays as the status's rule has it: `in_part` is green too.
                assert!(
                    status(&s, &screen, false).starts_with("\u{1b}[1;32m✓ Nothing needs a look")
                );
                // In the full account a fault is red and a limit is not.
                let red = screen.paint(RED, &view::shown(unstopped(&u.title)));
                assert_eq!(status(&s, &screen, true).contains(&red), fault, "{}", u.id);
            }
        }
    }

    #[test]
    fn a_failed_reading_of_this_mac_names_what_could_not_be_read_and_what_the_person_can_do() {
        let mut s = calm_status();
        let one = v1::Uncovered {
            scope: "this_mac".to_string(),
            count: 1,
            advice: "If they are yours, make them readable again.".to_string(),
            ..uncovered(
                "not-permitted",
                "you",
                false,
                "1 file could not be opened because of its permissions.",
                &[(
                    "~/Library/LaunchAgents/com.example.sync.plist",
                    Some("Permission denied"),
                )],
            )
        };
        let many = v1::Uncovered {
            scope: "this_mac".to_string(),
            count: 1_234_567,
            advice: "Nothing to do for now.".to_string(),
            ..uncovered(
                "could-not-read",
                "nothing",
                false,
                "1,234,567 things could not be read at the last check.",
                &[("~/a, b", None), ("~/.zshrc", None)],
            )
        };
        s.not_covered = vec![one, many];
        assert_eq!(
            faults_in(&s),
            [
                r#"! Could not read: "~/Library/LaunchAgents/com.example.sync.plist": "Permission denied" If they are yours, make them readable again."#,
                // A name holding ", " never passes for two; only the person's own advice is said.
                r#"! Could not read: "~/a, b", "~/.zshrc", and 1,234,565 more"#,
            ]
        );
        // Where a source said why of one, each name has what its source said after it.
        s.not_covered[1].examples[1].reason_text = Some("Is a directory".to_string());
        assert_eq!(
            faults_in(&s)[1],
            r#"! Could not read: "~/a, b"; "~/.zshrc": "Is a directory", and 1,234,565 more"#
        );
        // On a terminal a long path is cut in its middle, and the count of the rest is whole.
        s.not_covered[1].examples_text = vec![format!("{LONG}/poetry.lock")];
        s.not_covered[1].examples.clear();
        let text = status(&s, &Screen::terminal(60, false), false);
        let line = &fault_lines_of(&text)[1];
        assert!(
            line.contains('…') && line.ends_with(".lock\", and 1,234,566 more"),
            "{text}"
        );
    }

    #[test]
    fn a_failed_download_is_a_fault_line_even_when_the_data_kept_is_current() {
        let mut s = calm_status();
        assert!(faults_in(&s).is_empty());
        // One ecosystem's data could not be downloaded; what was read before is current, so the
        // core raises no cause and the headline stays calm, but the failure has its line.
        let feed =
            |ecosystem: &str, outcome: v1::FeedOutcome, read_at: Option<i64>| v1::FeedState {
                ecosystem: ecosystem.to_string(),
                outcome: outcome as i32,
                read_at,
                matched: true,
                ..Default::default()
            };
        let feeds = &mut s.vulnerability_data.as_mut().unwrap().feeds;
        feeds.push(feed("PyPI", v1::FeedOutcome::Failed, Some(CHECKED - 3600)));
        assert_eq!(
            faults_in(&s),
            [
                "! OSV data for PyPI not downloaded at the last check, the data read before stays in force"
            ]
        );
        // The catalogue too, and an ecosystem never read whole; an outcome this build does not
        // know is a failure.
        s.threats.as_mut().unwrap().outcome = 99;
        let feeds = &mut s.vulnerability_data.as_mut().unwrap().feeds;
        feeds.push(feed("crates.io", v1::FeedOutcome::Unspecified, None));
        assert_eq!(
            faults_in(&s),
            [
                "! CISA catalogue and OSV data for PyPI not downloaded at the last check, the data read before stays in force",
                "! OSV data for crates.io not downloaded, nothing of it is known yet",
            ]
        );
        // As the core gives them, with the causes that say the same: each said once.
        s.not_covered.push(uncovered(
            "vulnerability-list-not-downloaded",
            "nothing",
            false,
            "The list of vulnerabilities attackers are using could not be downloaded since the first check.",
            &[],
        ));
        s.not_covered.push(uncovered(
            "vulnerability-data-old",
            "nothing",
            false,
            "The list of known vulnerabilities could not be updated since the first check.",
            &[],
        ));
        assert_eq!(
            faults_in(&s),
            [
                "! The list of vulnerabilities attackers are using could not be downloaded since the first check",
                "! The list of known vulnerabilities could not be updated since the first check",
                "! OSV data for PyPI not downloaded at the last check, the data read before stays in force",
            ]
        );
        // What was read whole, or never asked for, is no failure.
        let mut s = calm_status();
        let feeds = &mut s.vulnerability_data.as_mut().unwrap().feeds;
        feeds.push(feed("PyPI", v1::FeedOutcome::NeverRead, None));
        assert!(faults_in(&s).is_empty());
    }

    #[test]
    fn each_headline_has_its_glyph_and_only_nothing_to_look_at_is_green() {
        let screen = Screen::terminal(80, true);
        let first = |s: &v1::Status| {
            status(s, &screen, false)
                .lines()
                .next()
                .unwrap()
                .to_string()
        };
        assert!(first(&calm_status()).starts_with("\u{1b}[1;32m✓ Nothing needs a look\u{1b}[0m"));
        // In part: the same words, and what keeps it from calm is a fault line under it.
        let mut s = calm_status();
        s.coverage.as_mut().unwrap().unreached_total = 1;
        assert_eq!(
            crate::headline::headed(s.clone()).headline,
            v1::Headline::InPart as i32
        );
        assert_eq!(first(&s), first(&calm_status()));
        // Something to look at: red when some of it is urgent, yellow when none is.
        let mut s = calm_status();
        s.needs_a_look = Some(v1::NeedsALook {
            total: 4,
            urgent_total: 1,
            by_rule: vec![group("watched.git-hook", v1::Level::Medium, 4, 1)],
            ..Default::default()
        });
        assert!(
            first(&s).starts_with("\u{1b}[1;31m● 4 things need a look · 1 urgent\u{1b}[0m"),
            "{}",
            first(&s)
        );
        let n = s.needs_a_look.as_mut().unwrap();
        (n.urgent_total, n.by_rule[0].urgent) = (0, 0);
        assert!(first(&s).starts_with("\u{1b}[1;33m● 4 things need a look\u{1b}[0m"));
        // Not known: never calm.
        let mut s = calm_status();
        s.this_mac.as_mut().unwrap().state = v1::ThisMacState::Unspecified as i32;
        assert!(first(&s).starts_with("\u{1b}[1;33m? Whether this Mac is watched is not known"));
        s.needs_a_look = None;
        let unknown = status(&s, &Screen::pipe(), false);
        assert!(
            unknown.starts_with("? No run of this build has looked for findings yet\n  Check this Mac now   immunity run\n"),
            "{unknown}"
        );
    }

    #[test]
    fn what_needs_a_look_is_listed_by_every_rule_with_the_command_that_shows_it() {
        let mut s = calm_status();
        let mut hook = listed(7, v1::Level::Critical, true, "~/dev/site".to_string());
        hook.package_text = Some("left-pad".to_string());
        hook.releases_text = vec!["1.0.7".to_string()];
        hook.short_title = "Malicious package in a project".to_string();
        hook.where_text = "~/dev/site/package-lock.json#node_modules/left-pad".to_string();
        if let Some(r) = hook.finding.as_mut() {
            r.rule = Some("lockfiles.malicious-package".to_string());
        }
        let mut by_rule = vec![v1::RuleCount {
            short_title: "Malicious package in a project".to_string(),
            ..group("lockfiles.malicious-package", v1::Level::Critical, 1, 1)
        }];
        // Nine rules more, none left out for a number.
        for i in 0..9 {
            by_rule.push(group(&format!("rule.{i}"), v1::Level::Medium, 2 + i, i % 2));
        }
        s.needs_a_look = Some(v1::NeedsALook {
            items: vec![v1::LookFinding {
                finding: Some(hook),
                ..Default::default()
            }],
            total: 1 + (0..9).map(|i| 2 + i).sum::<u64>(),
            urgent_total: 5,
            by_rule,
        });
        let text = status(&s, &Screen::pipe(), false);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            format!(
                "● 55 things need a look · 5 urgent   checked {}",
                view::utc(CHECKED)
            )
        );
        assert_eq!(
            lines[1],
            r#"  critical  Malicious package in a project: "left-pad" "1.0.7" in "~/dev/site""#
        );
        assert_eq!(
            lines[2],
            "            urgent   immunity finding f0000000007"
        );
        assert_eq!(lines[3], "  medium    Short title of rule.0");
        assert_eq!(lines[4], "            2 findings   immunity findings");
        assert_eq!(
            lines[6],
            "            3 findings, 1 urgent   immunity findings"
        );
        assert_eq!(lines[19], "  medium    Short title of rule.8");
        assert_eq!(lines[20], "            10 findings   immunity findings");
        assert_eq!(
            lines[21],
            "  Watching live · this Mac and 1,234,567 projects"
        );
        // A rule of one finding that the message does not list is counted like the others.
        s.needs_a_look.as_mut().unwrap().items.clear();
        let text = status(&s, &Screen::pipe(), false);
        assert_eq!(
            text.lines().nth(2),
            Some("            1 finding, urgent   immunity findings")
        );
        assert_eq!(
            text.lines().nth(1),
            Some("  critical  Malicious package in a project")
        );
    }

    #[test]
    fn a_running_first_check_says_when_it_started_and_its_stage_and_never_that_nothing_needed_a_look()
     {
        let mut s = calm_status();
        s.running = true;
        s.last_run = Some(v1::CheckMark {
            id: "run-1".to_string(),
            started_at: NOW - 120,
            finished_at: None,
        });
        s.last_finished_run = None;
        s.this_mac.as_mut().unwrap().checked_at = None;
        s.check_stage = Some(v1::CheckStage::Lockfiles as i32);
        s.check_stage_started_at = Some(NOW - 40);
        for text in [
            status(&s, &Screen::terminal(80, false), false),
            ran(&s, &Screen::terminal(80, false)),
        ] {
            assert!(
                text.starts_with("… The first check is running                                   started 2 min ago\n  Reading lockfiles for less than a minute\n"),
                "{text}"
            );
            assert!(!text.to_lowercase().contains("nothing need") && !text.contains('✓'));
        }
        // A stage this build cannot name, or one without its time, is no stage.
        for (stage, at) in [
            (Some(99), Some(NOW - 40)),
            (Some(0), Some(NOW - 40)),
            (Some(4), None),
        ] {
            (s.check_stage, s.check_stage_started_at) = (stage, at);
            let text = status(&s, &Screen::pipe(), false);
            assert_eq!(text.lines().count(), 1, "{text}");
        }
        // None running and none finished: what to run.
        s.running = false;
        s.last_run = None;
        let text = status(&s, &Screen::terminal(80, true), false);
        assert!(
            text.starts_with(
                "\u{1b}[1;33m? No check has finished yet\u{1b}[0m\n  Check this Mac now"
            ),
            "{text:?}"
        );
        assert!(text.contains("\u{1b}[36mimmunity run\u{1b}[0m"));
    }

    #[test]
    fn a_command_that_does_not_fit_beside_its_line_goes_on_the_next_line_set_to_the_right() {
        let mut s = calm_status();
        s.last_run = Some(v1::CheckMark {
            started_at: NOW - 600,
            ..Default::default()
        });
        // Its last line ends where the screen does, whatever the width.
        for width in [40, 50, 60, 80, 100] {
            let text = status(&s, &Screen::terminal(width, false), false);
            let line = text.lines().find(|l| l.contains("immunity run")).unwrap();
            assert_eq!(screen::columns(line), width, "{width}\n{text}");
        }
        // At 50 columns the words take 47 of them: the command goes under them, to the right.
        let narrow = status(&s, &Screen::terminal(50, false), false);
        assert!(
            narrow.ends_with(&format!(
                "  ! The check started 10 min ago did not finish\n{}immunity run\n",
                " ".repeat(38)
            )),
            "{narrow}"
        );
        // In a pipe the command follows the line.
        assert!(status(&s, &Screen::pipe(), false).contains(" did not finish   immunity run\n"));
    }

    #[test]
    fn the_default_text_never_says_coverage_reading_store_or_estate_but_in_what_a_source_said() {
        let mut s = status_of("x");
        s.not_covered.retain(|u| u.fault);
        for screen in screens() {
            let text = visible(&status(&s, &screen, false)).to_lowercase();
            for word in ["coverage", "reading", "store", "estate"] {
                // The source texts here that hold a word of them: a watcher's failure, and why the
                // answer is not fresh, given as the message gives it.
                let said = text
                    .replace("the watcher's latest write to the store failed", "")
                    .replace("no full check has finished on this store", "");
                assert!(!said.contains(word), "{word}\n{text}");
            }
        }
    }

    #[test]
    fn the_json_of_a_status_with_faults_and_limits_is_unchanged_by_what_its_text_leaves_out() {
        let s = crate::headline::headed(v1::Status {
            answered_at: NOW,
            needs_a_look: Some(v1::NeedsALook::default()),
            this_mac: Some(v1::ThisMac {
                state: v1::ThisMacState::Watched as i32,
                live: true,
                checked_at: Some(CHECKED),
                fresh: true,
                ..Default::default()
            }),
            watching: Some(v1::Watcher {
                failed: vec![v1::WatcherFailure {
                    what: crate::watch::READ.to_string(),
                    at: CHECKED,
                    detail_text: "busy".to_string(),
                }],
                ..Default::default()
            }),
            not_covered: vec![
                uncovered(
                    "could-not-read",
                    "nothing",
                    false,
                    "1 thing.",
                    &[("~/a", None)],
                ),
                uncovered(
                    "not-understood",
                    "nothing",
                    false,
                    "Some files.",
                    &[("x.lock", None)],
                ),
            ],
            ..Default::default()
        });
        let before = serde_json::to_string(&s).unwrap();
        let _ = status(&s, &Screen::terminal(80, true), false);
        let _ = status(&s, &Screen::pipe(), true);
        let _ = ran(&s, &Screen::pipe());
        assert_eq!(serde_json::to_string(&s).unwrap(), before);
        assert_eq!(before, JSON_GOLDEN);
    }

    /// The JSON of the status above, as this build gives it and gave it before its text changed.
    const JSON_GOLDEN: &str = r#"{"format":0,"answered_at":1794807960,"store_id":null,"running":false,"store":null,"cannot_judge":[],"rules":null,"watching":{"since_at":null,"last_read_at":null,"failed":[{"what":"read","at":1794807780,"detail_text":"busy"}],"cannot_see":[]},"this_mac":{"state":"watched","live":true,"checked_at":1794807780,"live_read_at":null,"watched":[],"fresh":true,"stale_reason":null,"fresh_for_seconds":0},"event_level":null,"not_covered":[{"id":"could-not-read","who":"nothing","scope":"","kind":"","title":"1 thing.","meaning":"","advice":"","count":0,"since_at":null,"value_text":null,"examples_text":["~/a"],"holds_on":"this_mac","examples":[{"name_text":"~/a","reason_text":null}],"class":"failed","fault":true},{"id":"not-understood","who":"nothing","scope":"","kind":"","title":"Some files.","meaning":"","advice":"","count":0,"since_at":null,"value_text":null,"examples_text":["x.lock"],"holds_on":"this_mac","examples":[{"name_text":"x.lock","reason_text":null}],"class":"no_reader","fault":false}],"last_run":null,"last_finished_run":null,"estate":null,"watched":null,"threats":null,"vulnerability_data":null,"vulnerabilities":null,"integrity":null,"no_reader_for":null,"coverage":null,"needs_a_look":{"items":[],"total":0,"urgent_total":0,"by_rule":[]},"answers_note":"","answered_outside_app":null,"statements_outside_app":null,"not_computed":[],"journal_seq":null,"login_job_installed":null,"watcher_restarting_since_at":null,"turned_on_at":null,"turned_off_at":null,"turned_on_latest":null,"check_stage":null,"check_stage_started_at":null,"headline":"in_part","headline_because":["watcher","not_covered"]}"#;
}
