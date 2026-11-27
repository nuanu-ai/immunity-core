//! The summary's section "As it happens": every program start on this Mac, checked against the
//! published rules. Three numbers first: program starts in the last day with a bar for each
//! hour, how many rules watch here now, and the matches of this week; a line of what was lost,
//! only when something was. Then the rules that matched this week, the most severe first, and
//! a grid of ATT&CK techniques for macOS, a row for each tactic in the matrix's order: one grey
//! square for each technique a rule watching now covers, told apart by its fill as a finding,
//! a match this week or watched. A technique no rule watches is not drawn: what the version
//! does not cover holds on every Mac and is kept in the documents and the commands' machine
//! form, not on the pages. Drawn in Rust as inline SVG and plain elements.
//!
//! Alive while open. A running watcher writes `view/live.js` after every reading of program
//! starts (`live`): numbers, rule ids of shipped rules and fixed words, nothing from an event,
//! a rule's text or the store's free text. One fixed script, `src/happens.js`, written beside
//! the pages, loads it every ten seconds and redraws the numbers in place; the header says how
//! fresh they are, or "not updating: no watcher is running" once the file is a minute old. It is
//! the page's only script, and it adds no text but its own words and numbers and, in a pop-up
//! over a technique's square, what the square carries as data. It also shows the button beside
//! each finding's command for an agent and copies the command's text, as the page wrote it.
//! Without it the section is complete as made, and says when it was made, and there is no button.
//!
//! Drawn from the messages the commands answer: the status (`event_level`, `rules`), the answer
//! of `immunity rules` and the findings (`view::Answers`). Nothing here reads the store or
//! decides again whether a rule watches.
//!
//! No false calm, the project's first invariant. Nothing is drawn as watching unless the status
//! says the rules watch (`RulesNow.watching`): while they do not, one named line says so in place
//! of the numbers, the rules and the grid. A technique is drawn as watched only for a rule
//! evaluated in full that watches now, which the status says by not naming it among the rules
//! that do not (`not_watching`); one named only by rules evaluated in part or not at all is not
//! drawn unless one of them matched. "0 lost" is said only when coverage over the day is full.
//! No square is in a state colour.
//!
//! The list of techniques is MITRE's, `rules/attack/macos.json` with its NOTICE, compiled in,
//! each with the first sentence of MITRE's description of it, which the pop-up shows.
//! Which techniques a rule covers is the rule's own `attack.t…` tags (`Rule.techniques_text`), a
//! sub-technique counted as its parent. Every string taken from a rule is data, printed through
//! `secrets::Name`.

use crate::contract::v1;
use crate::events::{self, Level};
use crate::secrets::Name;
use crate::sigma::{self, Rules};
use crate::view::{DETAILS, Out, esc};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::sync::OnceLock;

/// The section's anchor, which the app opens, and its heading.
pub const ANCHOR: &str = "as-it-happens";
pub const TITLE: &str = "As it happens";
/// How many rules that matched this week the section lists; the rest are counted.
const ROWS_SHOWN: usize = 10;
/// The section's script, and where it is written, relative to the store's folder, beside the
/// pages; the summary names it in its one script tag.
pub const SCRIPT: &str = include_str!("happens.js");
pub const SCRIPT_FILE: &str = "view/happens.js";
pub const SCRIPT_TAG: &str = "<script src=\"view/happens.js\"></script>";
/// What a running watcher writes after each reading of program starts, for the script.
pub const LIVE_FILE: &str = "view/live.js";
/// MITRE's techniques for macOS, as `rules/attack/NOTICE` says they were made.
const ATTACK: &str = include_str!("../rules/attack/macos.json");
/// MITRE's copyright designation, which its licence asks every copy to carry.
const MITRE: &str = "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.";

/// The ATT&CK techniques for macOS, by tactic in the matrix's order.
pub struct Attack {
    pub release: String,
    pub tactics: Vec<Tactic>,
    /// Every technique's name, by its id.
    pub names: BTreeMap<String, String>,
    /// Every technique's first sentence of MITRE's description, by its id.
    pub about: BTreeMap<String, String>,
}

pub struct Tactic {
    pub name: String,
    pub techniques: Vec<String>,
}

/// The data file, read once. It is compiled in, and a test reads it whole, so a malformed file
/// fails the build's tests, never a page.
pub fn attack() -> &'static Attack {
    static READ: OnceLock<Attack> = OnceLock::new();
    READ.get_or_init(|| {
        let v: Value = serde_json::from_str(ATTACK).expect("rules/attack/macos.json is JSON");
        let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
        // One field of every technique, by its id.
        let by_id = |field: &str| -> BTreeMap<String, String> {
            v["techniques"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| (text(&t["id"]), text(&t[field])))
                .collect()
        };
        Attack {
            release: text(&v["release"]),
            tactics: v["tactics"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| Tactic {
                    name: text(&t["name"]),
                    techniques: t["techniques"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(text)
                        .collect(),
                })
                .collect(),
            names: by_id("name"),
            about: by_id("description"),
        }
    })
}

/// A technique as the grid draws it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Square {
    /// A rule for it raised a finding that is open.
    Finding,
    /// A rule for it matched this week.
    Matched,
    /// A rule evaluated in full covers it, the level runs, and nothing matched: calm.
    Quiet,
    /// A rule evaluated in full covers it, but the level does not run: nothing watches it now.
    Would,
}

impl Square {
    fn class(self) -> &'static str {
        match self {
            Square::Finding => "look",
            Square::Matched => "hit",
            Square::Quiet => "calm",
            Square::Would => "would",
        }
    }

    fn said(self) -> &'static str {
        match self {
            Square::Finding => "a rule for it raised a finding",
            Square::Matched => "a rule for it matched this week",
            Square::Quiet => "watched, quiet",
            Square::Would => "has a rule, not watching now",
        }
    }

    /// What the legend calls it, as the panel's words.
    fn legend(self) -> &'static str {
        match self {
            Square::Finding => "A finding",
            Square::Matched => "A match this week",
            Square::Quiet => "Watched",
            Square::Would => "Not watching now",
        }
    }
}

/// A technique id as the grid counts it: a sub-technique as its parent.
fn parent(t: &str) -> &str {
    t.split('.').next().unwrap_or(t)
}

/// A rule as the section draws it: from the answer of `immunity rules`, with what the status
/// says the rules do now (`RulesNow`). Whether it watches is the status's word: checked in full,
/// the level running, and not named among the rules that do not watch (`not_watching`), whatever
/// the reason or a reason the reader does not know. A rule checked in part never watches.
pub struct Drawn<'a> {
    pub rule: &'a v1::Rule,
    /// Checked in full.
    pub full: bool,
    pub watching: bool,
    /// How many events it matched this week.
    pub week: u64,
}

/// Every rule the answer lists that could be read, in full, in part and not at all.
pub fn drawn<'a>(m: &'a v1::Rules, r: &v1::RulesNow) -> Vec<Drawn<'a>> {
    let on = r.watching == Some(true);
    let named = |name: &str| {
        (r.not_watching.iter()).any(|n| n.rule.as_ref().is_some_and(|x| x.name == name))
    };
    let of = |list: &'a [v1::ShippedRule], full: bool| {
        list.iter().filter_map(move |s| {
            let rule = s.rule.as_ref()?;
            Some(Drawn {
                rule,
                full,
                watching: full && on && !named(&rule.name),
                week: s.matches_last_week.unwrap_or(0),
            })
        })
    };
    let all = of(&m.evaluated, true).chain(of(&m.in_part, false));
    all.chain(of(&m.not_evaluated, false)).collect()
}

/// The techniques the rules name, as parents, for the rules `which` picks.
fn named<'a>(rules: &'a [Drawn], which: impl Fn(&Drawn) -> bool) -> BTreeSet<&'a str> {
    (rules.iter().filter(|d| which(d)))
        .flat_map(|d| d.rule.techniques_text.iter().map(|t| parent(t)))
        .collect()
}

/// Matches this week by technique, as parents: for each, the matches of the rules that name it,
/// a rule counted once however many of its sub-techniques it names.
fn matches_by_technique<'a>(rules: &'a [Drawn]) -> BTreeMap<&'a str, u64> {
    let mut out: BTreeMap<&str, u64> = BTreeMap::new();
    for d in rules.iter().filter(|d| d.week > 0) {
        let named: BTreeSet<&str> = d.rule.techniques_text.iter().map(|t| parent(t)).collect();
        for t in named {
            *out.entry(t).or_default() += d.week;
        }
    }
    out
}

/// The step of a technique's tint by its matches this week, three at most: one, two to nine,
/// ten or more. The number itself is in the square's title.
fn step(n: u64) -> &'static str {
    match n {
        ..=1 => "s1",
        2..=9 => "s2",
        _ => "s3",
    }
}

/// Every tactic with the techniques a rule checked in full covers, or a rule matched or raised
/// a finding for, each in its state, the most telling first and then by id. Any other technique
/// is not drawn, and a tactic with none is left out: the grid shows the rules taken and what
/// they found, not what is not covered. `raised`: the names of rules with an open finding.
pub fn grid<'a>(
    attack: &'a Attack,
    rules: &[Drawn],
    raised: &BTreeSet<&str>,
) -> Vec<(&'a Tactic, Vec<(&'a str, Square)>)> {
    let watched = named(rules, |d| d.full);
    let now = named(rules, |d| d.watching);
    let matched = named(rules, |d| d.week > 0);
    let found = named(rules, |d| raised.contains(d.rule.name.as_str()));
    attack
        .tactics
        .iter()
        .map(|t| {
            let mut squares: Vec<(&str, Square)> = t
                .techniques
                .iter()
                .map(String::as_str)
                .filter(|tech| {
                    watched.contains(tech) || matched.contains(tech) || found.contains(tech)
                })
                .map(|tech| {
                    let square = if found.contains(tech) {
                        Square::Finding
                    } else if matched.contains(tech) {
                        Square::Matched
                    } else if now.contains(tech) {
                        Square::Quiet
                    } else {
                        Square::Would
                    };
                    (tech, square)
                })
                .collect();
            squares.sort_by_key(|(tech, square)| (*square, *tech));
            (t, squares)
        })
        .filter(|(_, squares)| !squares.is_empty())
        .collect()
}

/// One rule that matched this week, as a row.
struct Row<'a> {
    rule: &'a v1::Rule,
    count: u64,
    /// Its finding: the id, and whether it is open, else answered and in force.
    finding: Option<(&'a str, bool)>,
}

/// A number as a person reads it, thousands separated.
fn num(n: u64) -> String {
    crate::view::counted(i64::try_from(n).unwrap_or(i64::MAX), "", "")
        .trim_end()
        .to_string()
}

/// The level's state as one of the fixed words `events` names, any other word `failed`: neither
/// the store nor a message is trusted to hold only those.
fn fixed(state: &str) -> &'static str {
    let states = [
        events::NOT_INSTALLED,
        events::RUNNING,
        events::REFUSED,
        events::FAILING,
        events::SILENT,
        events::FAILED,
    ];
    (states.into_iter().find(|s| *s == state)).unwrap_or(events::FAILED)
}

/// The level's state as the store holds it, in the fixed words.
pub fn known(l: Option<&Level>) -> &'static str {
    l.map_or("none", |l| fixed(&l.state))
}

/// The level's state as the message gives it, in the same fixed words.
fn known_of(l: Option<&v1::EventLevel>) -> &'static str {
    l.map_or("none", |l| {
        let word = v1::CollectorState::try_from(l.state).map(|s| s.as_str_name());
        fixed(
            &word
                .unwrap_or("")
                .trim_start_matches("COLLECTOR_STATE_")
                .to_ascii_lowercase(),
        )
    })
}

/// A rule's place on the scale of severity, the most severe highest; `None` for a rule of a set
/// that states no level, which is not on it. A level the reader does not know is read as the
/// highest (`common.proto`).
fn rank(rule: &v1::Rule) -> Option<i32> {
    use v1::Level as L;
    match L::try_from(rule.level) {
        Ok(L::NotStated) => None,
        Ok(L::Informational | L::Low | L::Medium | L::High | L::Critical) => Some(rule.level),
        _ => Some(L::Critical as i32),
    }
}

/// The section, from the status, the answer of `immunity rules` and the findings, made at `now`.
/// While the level does not run, one line says so, named, in place of the numbers and the grid.
pub fn draw(
    out: &mut String,
    r: &v1::Status,
    m: &v1::Rules,
    found: &v1::Findings,
    now: i64,
) -> Out {
    let rules_now = r.rules.clone().unwrap_or_default();
    let level = r.event_level.as_ref();
    let rules = drawn(m, &rules_now);
    let matched_ids: Vec<String> = (rules.iter().filter(|d| d.week > 0))
        .map(|d| Name::given(&d.rule.id_text).attr())
        .collect();
    writeln!(
        out,
        "<section id=\"{ANCHOR}\" data-state=\"{}\" data-matched=\"{}\">\n<div class=\"wsh\"><h2>{TITLE}</h2><span class=\"n\">every program start, checked against published rules</span><span class=\"live\" data-live=\"said\">as made, {}</span></div>\n<p class=\"first\" data-live=\"moved\" hidden></p>",
        known_of(level),
        matched_ids.join(" "),
        crate::view::when(now, now)
    )?;
    let Some(l) = level.filter(|_| rules_now.watching == Some(true)) else {
        let words = level.and_then(|l| l.in_words.as_ref());
        let (state, notes) = match words {
            Some(w) => (w.state.as_str(), w.notes.join(" ")),
            None => (
                "not looked for yet",
                "The next check looks for them.".to_string(),
            ),
        };
        writeln!(
            out,
            "<p class=\"first\"><strong>Program starts: {}.</strong> {} No rule is watching now.</p>\n<p class=\"first\"><a href=\"{DETAILS}/{}.html\">Published rules, each with what it looks for</a></p>\n{SCRIPT_TAG}\n</section>",
            esc(state),
            esc(&notes),
            crate::pages::RULES,
        )?;
        return Ok(());
    };
    out.push_str("<div class=\"stats\">\n");
    let day = |s: &Option<v1::Span>| s.as_ref().map_or(0, |s| s.last_day);
    stat(
        out,
        ("Program starts in the last day", "last_day"),
        &num(day(&l.program_starts)),
        &bars(&l.program_starts_by_hour.clone().unwrap_or_default()),
        &["by hour, last 24 hours".to_string()],
    )?;
    watching(out, &rules_now, l)?;
    stat(
        out,
        ("Matches this week", "week"),
        &num(m.matches_last_week.unwrap_or(0)),
        "",
        &["only a rule rated high raises a finding; the rest are counted".to_string()],
    )?;
    out.push_str("</div>\n");
    lost(out, l)?;
    matched(out, &rules, found)?;
    cover(out, &rules, found)?;
    out.push_str(SCRIPT_TAG);
    out.push_str("\n</section>\n");
    Ok(())
}

/// One of the three numbers: what it counts, the number, a drawing under it, and quieter lines.
/// `live` names the number for the script, and its lines as `<live>-note`.
fn stat(
    out: &mut String,
    (title, live): (&str, &str),
    big: &str,
    drawing: &str,
    notes: &[String],
) -> Out {
    write!(
        out,
        "<div class=\"stat\"><span class=\"st\">{}</span><span class=\"sv\" data-live=\"{live}\">{}</span>{drawing}",
        esc(title),
        esc(big)
    )?;
    for n in notes {
        write!(
            out,
            "<span class=\"ss\" data-live=\"{live}-note\">{}</span>",
            esc(n)
        )?;
    }
    out.push_str("</div>\n");
    Ok(())
}

/// What was lost over the last day as the number says it. "0" only when nothing was lost,
/// unreadable or deleted before it was read; a restart of the collector is a loss of unknown
/// size, said as "some" or as "at least". A file the size cap deleted after it was read lost
/// nothing (`Tally::gaps`).
fn lost_shown(d: &events::Tally) -> String {
    if d.whole() {
        return "0".to_string();
    }
    let unknown = d.unknown_gaps + d.unreadable + d.removed_unread > 0;
    match (d.lost, unknown) {
        (0, _) => "some".to_string(),
        (n, true) => format!("{}+", num(n as u64)),
        (n, false) => num(n as u64),
    }
}

/// The last day's counts of program starts as the message gives them.
fn last_day(l: &v1::EventLevel) -> events::Tally {
    let day = |s: &Option<v1::Span>| s.as_ref().map_or(0, |s| s.last_day as i64);
    events::Tally {
        starts: day(&l.program_starts),
        lost: day(&l.lost),
        unknown_gaps: day(&l.unknown_losses),
        unreadable: day(&l.unreadable_lines),
        other: day(&l.other_messages),
        removed_cap: day(&l.files_removed_by_cap),
        removed_unread: day(&l.files_removed_unread),
    }
}

/// What was lost over the last day, in one line with the reader's own caveats, shown only when
/// something was; the script shows it when a loss comes later. What the collector does not
/// keep is said in a line of its own even when nothing was lost.
fn lost(out: &mut String, l: &v1::EventLevel) -> Out {
    let day = last_day(l);
    let whole = day.whole();
    let mut notes = (l.in_words.as_ref()).map_or(String::new(), |w| w.notes.join(" "));
    if whole {
        if !notes.is_empty() {
            writeln!(out, "<p class=\"first note\">{}</p>", esc(&notes))?;
        }
        notes.clear();
    }
    writeln!(
        out,
        "<p class=\"first\" data-live=\"lostline\"{}>Program starts lost in the last day: <span data-live=\"lost\">{}</span>. <span data-live=\"lost-note\">{}</span></p>",
        if whole { " hidden" } else { "" },
        esc(&lost_shown(&day)),
        esc(&notes)
    )?;
    Ok(())
}

/// What a running watcher writes to `LIVE_FILE` after a reading of program starts, at `now`:
/// the level's numbers, its state as a fixed word, the caveats in their few words, and how
/// many program starts matched each shipped rule this week, by id. Nothing else: a title or
/// anything read from an event stays in the page as it was made.
pub fn live(l: Option<&Level>, now: i64) -> Value {
    let series = |s: &events::Series| serde_json::json!({ "ends_at_seconds": s.ends_at, "step": s.step, "counts": s.counts });
    let Some(level) = l else {
        return serde_json::json!({ "written_at_seconds": now, "state": known(None) });
    };
    let said = events::words(level);
    let rules = Rules::shipped();
    let week: BTreeMap<&str, i64> = level
        .matches_last_week
        .iter()
        .filter_map(|(id, n)| Some((rules.by_id(id)?.meta.as_ref()?.id.as_str(), *n)))
        .collect();
    serde_json::json!({
        "written_at_seconds": now,
        "state": known(l),
        "state_words": said.state,
        "last_day": level.last_day.starts,
        "last_hour": level.starts_by_minute.counts.iter().sum::<i64>(),
        "by_hour": series(&level.starts_by_hour),
        "by_minute": series(&level.starts_by_minute),
        "lost": lost_shown(&level.last_day),
        "caveats": said.caveats.iter().map(|c| serde_json::json!({ "kind": c.kind, "short": c.short })).collect::<Vec<_>>(),
        "matches_last_week": week,
        // File events of the last day while the rules for them watch, else null.
        "file_events_last_day": level.files_watched().then_some(level.files.last_day.files),
    })
}

/// `live` as the script file the page loads: one assignment. Written whole and then moved into
/// place, so that the page never loads half of one.
pub fn write_live(folder: &std::path::Path, l: Option<&Level>, now: i64) -> std::io::Result<()> {
    let path = folder.join(LIVE_FILE);
    std::fs::create_dir_all(path.parent().unwrap_or(folder))?;
    let part = path.with_extension("js.part");
    std::fs::write(&part, format!("window.immunityLive = {};\n", live(l, now)))?;
    std::fs::rename(&part, &path)
}

/// How many rules watch on this Mac now, and why some taken here do not: the collector here
/// records no file events. Drawn only while the level runs. How much of the published sets is
/// evaluated at all holds on every Mac and is not said on the pages; the page of rules lists
/// each rule with what it needs, and the status gives the counts.
fn watching(out: &mut String, r: &v1::RulesNow, l: &v1::EventLevel) -> Out {
    let files_watched = r.file_events_collected == Some(true);
    let mut notes: Vec<String> =
        vec!["published rules, each checking every program start".to_string()];
    if !files_watched {
        // Named on the rules page and in the status; here, how many and why, quietly.
        notes.push(format!(
            "{} for files created or renamed do not watch: the collector here records program starts only",
            r.file_rules
        ));
    }
    if let Some(note) = r.judged_note.as_deref() {
        notes.push(note.to_string());
    }
    // File events, many a second, are said once, quietly, here, where the rules that read
    // them are counted; never as a number beside program starts.
    let mut files = String::new();
    if files_watched {
        let n = (l.file_events.as_ref().and_then(|f| f.events.as_ref())).map_or(0, |s| s.last_day);
        write!(
            files,
            "<span class=\"ss\" data-live=\"files\">{}</span>",
            esc(&files_said(n))
        )?;
    }
    // The number, its caption and the rest of its notes, then the file events last.
    let mut drawn = String::new();
    stat(
        &mut drawn,
        ("Rules watching now", "watching"),
        &num(r.watching_rules.unwrap_or(0)),
        "",
        &notes,
    )?;
    let end = drawn.len() - "</div>\n".len();
    drawn.insert_str(end, &files);
    out.push_str(&drawn);
    Ok(())
}

/// The file events of the last day, as the section says them.
fn files_said(n: u64) -> String {
    format!(
        "{} checked in the last day",
        crate::view::counted(
            i64::try_from(n).unwrap_or(i64::MAX),
            "file event",
            "file events"
        )
    )
}

/// Program starts by hour as bars, the last hour on the right, each with its hours and count in
/// its title, in the third colour of text. An hour with none is drawn as a line of the
/// separator's colour, never as a bar.
fn bars(h: &v1::Series) -> String {
    const W: f64 = 240.0;
    const H: f64 = 32.0;
    const GAP: f64 = 2.0;
    let n = h.counts.len().max(1);
    let bw = (W - GAP * (n as f64 - 1.0)) / n as f64;
    let top = h.counts.iter().copied().max().unwrap_or(0).max(1) as f64;
    let mut svg = format!(
        "<svg class=\"hours\" data-live=\"hours\" viewBox=\"0 0 {W} {H}\" role=\"img\" aria-label=\"Program starts by hour over the last 24 hours; the most in one hour: {}\">",
        num(top as u64)
    );
    let hhmm = |t: i64| crate::view::utc(t)[11..16].to_string();
    for (i, c) in h.counts.iter().enumerate() {
        let end = h.ends_at - (n - 1 - i) as i64 * 3600;
        let (bh, fill) = if *c > 0 {
            ((*c as f64 / top * H).max(1.5), "var(--bar)")
        } else {
            (1.5, "var(--sep)")
        };
        let count = i64::try_from(*c).unwrap_or(i64::MAX);
        let _ = write!(
            svg,
            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{bw:.1}\" height=\"{bh:.1}\" rx=\"1\" style=\"fill:{fill}\"><title>{}–{} UTC: {}</title></rect>",
            i as f64 * (bw + GAP),
            H - bh,
            hhmm(end - 3600),
            hhmm(end),
            crate::view::counted(count, "program start", "program starts")
        );
    }
    svg.push_str("</svg>");
    svg
}

/// One rule's row: its title as data in an element of its own and its set, the level its
/// authors give it, the count, and its finding, linked, or "Counted".
fn rule_row(out: &mut String, row: &Row) -> Out {
    let state = match row.finding {
        Some((id, true)) => format!("<a href=\"#{}\">Finding</a>", esc(id)),
        Some((id, false)) => format!("<a href=\"#answered-{}\">Finding, answered</a>", esc(id)),
        None if rank(row.rule).is_some_and(|r| r >= v1::Level::High as i32) => {
            "Finding".to_string()
        }
        None => "Counted".to_string(),
    };
    let level = match rank(row.rule) {
        None => sigma::NO_LEVEL.to_string(),
        Some(_) => crate::text::word::<v1::Level>(row.rule.level),
    };
    writeln!(
        out,
        "<div class=\"rr\" data-rule=\"{}\"><span class=\"rt\">{} ({})</span><span class=\"rl\">{}</span><span class=\"rc\">{}</span><span class=\"rs\">{state}</span></div>",
        Name::given(&row.rule.id_text).attr(),
        Name::given(&row.rule.title_text).html(),
        esc(&row.rule.set),
        esc(&level),
        num(row.count),
    )?;
    Ok(())
}

/// The rules that matched this week, most severe first, then by count: each with its title as
/// data, its level, a bar for its count, the count, and its finding or "Counted". Its finding is
/// the first open one of the rule in the list's order, else the latest answered.
fn matched(out: &mut String, rules: &[Drawn], found: &v1::Findings) -> Out {
    let finding_of = |name: &str| -> Option<(&str, bool)> {
        let of = (found.findings.iter())
            .filter_map(|l| Some((l, l.finding.as_ref()?)))
            .filter(|(_, r)| r.rule.as_deref() == Some(name));
        let mut answered = None;
        for (l, r) in of {
            if crate::pages::findings_table::is_open(r.state) {
                return Some((r.id.as_str(), true));
            }
            let at = l.answer.as_ref().filter(|a| a.in_force).map(|a| a.given_at);
            if at.is_some() && answered.is_none_or(|(_, then)| at > then) {
                answered = Some((r.id.as_str(), at));
            }
        }
        answered.map(|(id, _)| (id, false))
    };
    let mut rows: Vec<Row> = (rules.iter().filter(|d| d.week > 0))
        .map(|d| Row {
            rule: d.rule,
            count: d.week,
            finding: finding_of(&d.rule.name),
        })
        .collect();
    out.push_str("<div class=\"matched\">\n<div class=\"rr rh\"><span>Rule that matched this week</span><span>Its authors rate it</span><span class=\"rc\">Matches</span><span>Became</span></div>\n");
    matched_rows(out, &mut rows)?;
    writeln!(
        out,
        "<p class=\"all\">{}<a href=\"{DETAILS}/{}.html\">Published rules, each with what it looks for</a></p>\n</div>",
        shown_said(&rows),
        crate::pages::RULES,
    )?;
    Ok(())
}

/// The rows of the rules that matched, sorted and cut. Most severe first, then by count. The
/// rules of a set that states no level are not ranked among them: they are a group of their
/// own after them, by count, with its own heading, count and cut.
fn matched_rows(out: &mut String, rows: &mut [Row]) -> Out {
    rows.sort_by(|a, b| {
        rank(b.rule)
            .cmp(&rank(a.rule))
            .then(b.count.cmp(&a.count))
            .then_with(|| (&a.rule.title_text, &a.rule.set).cmp(&(&b.rule.title_text, &b.rule.set)))
    });
    let (ranked, unranked): (Vec<&Row>, Vec<&Row>) =
        rows.iter().partition(|r| rank(r.rule).is_some());
    if rows.is_empty() {
        out.push_str("<p class=\"none\" data-live=\"none\">No rule matched this week.</p>\n");
    }
    for row in ranked.iter().take(ROWS_SHOWN) {
        rule_row(out, row)?;
    }
    if !unranked.is_empty() {
        writeln!(
            out,
            "<div class=\"sh grp\"><h4>{}</h4><span class=\"n\">{}, counted and not ranked by severity</span></div>",
            esc(&crate::pages::capital(sigma::NO_LEVEL_GROUP)),
            crate::view::counted(unranked.len() as i64, "rule", "rules")
        )?;
        for row in unranked.iter().take(ROWS_SHOWN) {
            rule_row(out, row)?;
        }
    }
    out.push_str("<p class=\"all\" data-live=\"more\" hidden></p>\n");
    Ok(())
}

/// What the cut left out, said for each group apart: the rules with a level by severity, the
/// rules of a set that states no level by count.
fn shown_said(rows: &[Row]) -> String {
    let ranked = rows.iter().filter(|r| rank(r.rule).is_some()).count();
    let unranked = rows.len() - ranked;
    let mut shown = String::new();
    if ranked > ROWS_SHOWN {
        shown.push_str(&format!(
            "{ranked} rules with a level matched this week; the {ROWS_SHOWN} most severe are shown · "
        ));
    }
    if unranked > ROWS_SHOWN {
        shown.push_str(&format!(
            "{unranked} rules {} matched this week; the {ROWS_SHOWN} counted most are shown · ",
            sigma::NO_LEVEL_GROUP
        ));
    }
    shown
}

/// One technique's square. Its id, name and state are its title, which a browser shows without
/// the script, and its accessible name; the same and MITRE's first sentence of what the
/// technique is are data the script's pop-up sets as text. MITRE's words are written in the
/// printer's attribute form (`Name::attr`), the state in the core's. `now`: its finding needs the
/// person now.
fn square(
    out: &mut String,
    class: &str,
    (tech, name, about): (&str, &str, &str),
    said: &str,
    now: bool,
) -> Out {
    let attr = |s: &str| Name::of(s).attr();
    let (tech, name, about, said) = (attr(tech), attr(name), attr(about), esc(said));
    write!(
        out,
        "<span class=\"m {class}\" title=\"{tech} {name}: {said}\" role=\"img\" aria-label=\"{tech} {name}: {said}\" data-t=\"{tech}\" data-n=\"{name}\" data-d=\"{about}\" data-s=\"{said}\"{}></span>",
        if now { " data-now" } else { "" }
    )?;
    Ok(())
}

/// The grid of techniques, drawn only while the level runs: a legend, a row for each tactic
/// with a square for each technique watched now or that a rule matched or raised a finding
/// for, and what the squares are, with MITRE's notice. A technique whose rules do not watch
/// now (rules for file events where the collector records none) is not drawn.
fn cover(out: &mut String, rules: &[Drawn], found: &v1::Findings) -> Out {
    let attack = attack();
    // The rules of the open findings, and of those that need the person now.
    let raised_by = |urgent_only: bool| -> BTreeSet<&str> {
        (found.findings.iter().filter_map(|l| l.finding.as_ref()))
            .filter(|r| crate::pages::findings_table::is_open(r.state))
            .filter(|r| !urgent_only || r.urgent)
            .filter_map(|r| r.rule.as_deref())
            .collect()
    };
    let raised = raised_by(false);
    // The techniques of a finding that needs the person now: their squares are red, the rest of
    // the findings' orange, as the findings table groups them.
    let urgent_names = raised_by(true);
    let urgent = named(rules, |d| urgent_names.contains(d.rule.name.as_str()));
    let grid: Vec<(&Tactic, Vec<(&str, Square)>)> = grid(attack, rules, &raised)
        .into_iter()
        .map(|(t, squares)| {
            let watched: Vec<(&str, Square)> = squares
                .into_iter()
                .filter(|(_, s)| *s != Square::Would)
                .collect();
            (t, watched)
        })
        .filter(|(_, squares)| !squares.is_empty())
        .collect();
    out.push_str("<div class=\"covers\">\n<div class=\"wsh3\"><h3>What the rules watch</h3><ul class=\"legend\">");
    if !urgent.is_empty() {
        out.push_str(
            "<li><span class=\"m look\" data-now aria-hidden=\"true\"></span>Needs you now</li>",
        );
    }
    for s in [Square::Finding, Square::Matched, Square::Quiet] {
        write!(
            out,
            "<li><span class=\"m {}\" aria-hidden=\"true\"></span>{}</li>",
            s.class(),
            s.legend()
        )?;
    }
    out.push_str("</ul></div>\n<div class=\"tactics\">\n");
    let counts = matches_by_technique(rules);
    if grid.is_empty() {
        out.push_str("<p class=\"meta\">No rule watching now names a technique.</p>\n");
    }
    for (tactic, squares) in &grid {
        write!(
            out,
            "<div class=\"tactic\"><span class=\"tn2\">{}</span><span class=\"sq\">",
            Name::of(&tactic.name).html()
        )?;
        for (tech, s) in squares {
            let name = attack.names.get(*tech).map_or("", String::as_str);
            // A match's tint is stronger with more matches, and its title says how many.
            let (class, said) = match s {
                Square::Matched => {
                    let n = counts.get(tech).copied().unwrap_or(0);
                    (
                        format!("{} {}", s.class(), step(n)),
                        format!(
                            "{}, {} {}",
                            s.said(),
                            n,
                            if n == 1 { "match" } else { "matches" }
                        ),
                    )
                }
                _ => (s.class().to_string(), s.said().to_string()),
            };
            // A technique of a finding that needs the person now is always drawn as a finding.
            let now = urgent.contains(tech);
            let about = attack.about.get(*tech).map_or("", String::as_str);
            square(out, &class, (tech, name, about), &said, now)?;
        }
        out.push_str("</span></div>\n");
    }
    out.push_str("</div>\n");
    let listed: BTreeSet<&str> = attack.names.keys().map(String::as_str).collect();
    let all = named(rules, |_| true);
    let outside: Vec<&str> = all.difference(&listed).copied().collect();
    // The techniques the rules name are the rules' words: each through the printer.
    let mut said = esc(
        "Each square is one ATT&CK technique for macOS that a published rule watches now, grouped by what an attacker is trying to do.",
    );
    if !outside.is_empty() {
        let named: Vec<String> = outside.iter().map(|t| Name::given(t).html()).collect();
        said.push_str(&format!(
            " Named by the rules but not listed by ATT&amp;CK for macOS: {}.",
            named.join(", ")
        ));
    }
    writeln!(
        out,
        "<p class=\"meta\">{said}</p>\n<p class=\"meta\">Techniques from MITRE ATT&amp;CK {}. {}</p>\n</div>",
        Name::of(&attack.release).html(),
        esc(MITRE)
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Series, Tally};

    const PADDING: &str = "95361ce5-c891-4b0a-87ca-e24607884a96";
    const SW_VERS: &str = "5de06a6f-673a-4fc0-8d48-bcfe3837b033";

    fn counts(grid: &[(&Tactic, Vec<(&str, Square)>)], s: Square) -> usize {
        grid.iter()
            .flat_map(|(_, squares)| squares.iter())
            .filter(|(_, x)| *x == s)
            .count()
    }

    /// The answer of `immunity rules` and what the status says the rules do now, for these rules
    /// and this level, with the level's matches of the week.
    fn answers(rules: &Rules, l: Option<&Level>) -> (v1::Rules, v1::RulesNow) {
        let none = BTreeMap::new();
        let week = l.map_or(&none, |l| &l.matches_last_week);
        let m = rules.message(Some((&none, week)));
        (m, crate::status::rules_now_of(rules, l))
    }

    /// A level that runs, its collector recording file events and every field it may keep
    /// arriving: every rule checked in full watches.
    fn all_arriving() -> Level {
        let on = crate::events::Arrival::Kept(Some(1));
        Level {
            arrivals: crate::events::Arrivals::from([on; 5]),
            files: crate::events::Files {
                collected: true,
                ..Default::default()
            },
            ..level(Tally::default())
        }
    }

    /// The grid as the summary draws it for these rules, this level and the rules of open
    /// findings, by name.
    fn grid_of<'a>(
        rules: &Rules,
        l: Option<&Level>,
        raised: &BTreeSet<&str>,
    ) -> Vec<(&'a Tactic, Vec<(&'a str, Square)>)> {
        let (m, r) = answers(rules, l);
        grid(attack(), &drawn(&m, &r), raised)
    }

    #[test]
    fn the_squares_drawn_are_exactly_the_techniques_a_rule_checked_in_full_covers_as_the_rules_and_mitre_say()
     {
        // A square is a claim that a rule watches the technique. It is counted here again from
        // the raw sources: the `attack.t…` tags in the text of each rule evaluated in full, and
        // MITRE's file as it is, so a technique drawn for a rule that is not checked, one
        // missing from its tactic, or a tactic drawn empty, shows.
        let data: Value = serde_json::from_str(ATTACK).unwrap();
        let rules = Rules::shipped();
        let mut tagged: BTreeSet<String> = BTreeSet::new();
        for l in rules
            .rules
            .iter()
            .filter(|l| l.placement == sigma::Placement::Evaluated)
        {
            let text = l.source.files.iter().find(|(f, _)| *f == l.file).unwrap().1;
            for word in text.split_whitespace() {
                // A tag in a YAML list or in a JSON one, as the translated rules write theirs.
                let word = word.trim_matches(['[', ']', '"', ',']);
                if let Some(t) = word.strip_prefix("attack.t") {
                    tagged.insert(format!("T{}", t.split('.').next().unwrap()));
                }
            }
        }
        let a = attack();
        let grid = grid_of(rules, Some(&all_arriving()), &BTreeSet::new());
        let mut drawn = grid.iter();
        for raw in data["tactics"].as_array().unwrap() {
            let covered: BTreeSet<&str> = raw["techniques"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t.as_str().unwrap())
                .filter(|t| tagged.contains(*t))
                .collect();
            // A tactic with no technique a rule covers is not drawn at all; the rest keep the
            // matrix's order.
            if covered.is_empty() {
                assert!(
                    grid.iter()
                        .all(|(t, _)| t.name != raw["name"].as_str().unwrap()),
                    "{}",
                    raw["name"]
                );
                continue;
            }
            let (tactic, squares) = drawn.next().unwrap();
            assert_eq!(tactic.name, raw["name"].as_str().unwrap());
            let shown: BTreeSet<&str> = squares.iter().map(|(t, _)| *t).collect();
            assert_eq!(shown, covered, "{}", tactic.name);
            assert!(squares.iter().all(|(_, s)| *s == Square::Quiet));
        }
        assert!(drawn.next().is_none());
        // MITRE's file as made: the matrix's order, and a name for every technique drawn.
        assert_eq!(a.release, "v20.1");
        assert_eq!(a.names.len(), 154);
        assert_eq!(a.tactics.first().unwrap().name, "Initial Access");
        assert_eq!(a.tactics.last().unwrap().name, "Impact");
        assert!(
            a.tactics
                .iter()
                .flat_map(|t| &t.techniques)
                .all(|t| a.names.contains_key(t))
        );
    }

    #[test]
    fn a_square_is_drawn_as_watched_only_while_the_status_says_the_rules_watch_and_names_none_of_its_rules()
     {
        // No false calm: while program starts are not seen, a technique with a rule is drawn
        // as what would be watched, never as watched and quiet. While they are, a rule the status
        // names among those that do not watch, for any reason or one the reader does not know,
        // watches nothing.
        let none = BTreeSet::new();
        let off = grid_of(Rules::shipped(), None, &none);
        let on = grid_of(Rules::shipped(), Some(&all_arriving()), &none);
        assert_eq!(counts(&off, Square::Quiet), 0);
        assert_eq!(counts(&on, Square::Would), 0);
        assert!(counts(&on, Square::Quiet) > 0);
        assert_eq!(counts(&off, Square::Would), counts(&on, Square::Quiet));
        let (m, mut r) = answers(Rules::shipped(), Some(&all_arriving()));
        assert!(r.not_watching.is_empty());
        r.not_watching = (m.evaluated.iter().filter_map(|s| s.rule.clone()))
            .map(|rule| v1::NotWatching {
                rule: Some(rule),
                reason: 99,
                not_arriving: Vec::new(),
            })
            .collect();
        let named = grid(attack(), &drawn(&m, &r), &none);
        assert_eq!(counts(&named, Square::Quiet), 0);
        assert_eq!(counts(&named, Square::Would), counts(&on, Square::Quiet));
    }

    #[test]
    fn a_finding_outranks_a_match_and_a_match_outranks_calm_on_every_tactic_of_its_technique() {
        // The red square is the technique of the open finding's rule, wherever ATT&CK lists
        // it; a rule that only matched is drawn as such, never as calm.
        let a = attack();
        let mut l = all_arriving();
        l.matches_last_week = BTreeMap::from([(SW_VERS.to_string(), 3), (PADDING.to_string(), 1)]);
        let padding = Rules::shipped().by_id(PADDING).unwrap();
        let raised = BTreeSet::from([padding.meta.as_ref().unwrap().name.as_str()]);
        let g = grid_of(Rules::shipped(), Some(&l), &raised);
        let state = |tech: &str| -> Vec<Square> {
            g.iter()
                .flat_map(|(_, s)| s.iter())
                .filter(|(t, _)| *t == tech)
                .map(|(_, s)| *s)
                .collect()
        };
        let in_tactics = |tech: &str| {
            a.tactics
                .iter()
                .filter(|t| t.techniques.iter().any(|x| x == tech))
                .count()
        };
        assert_eq!(state("T1027"), vec![Square::Finding; in_tactics("T1027")]);
        assert_eq!(state("T1082"), vec![Square::Matched; in_tactics("T1082")]);
        assert_eq!(counts(&g, Square::Finding), in_tactics("T1027"));
        // The most telling first within a tactic.
        for (_, squares) in &g {
            assert!(squares.windows(2).all(|w| w[0].1 <= w[1].1));
        }
    }

    /// A rule for macOS program starts tagged with a technique; `also` is a second alternative
    /// of its selection.
    const IN_PART: &str = "title: Checked in part
id: 11111111-1111-4111-8111-111111111111
status: test
level: medium
tags:
    - attack.t1021.004
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        - Image|endswith: '/ssh'
        - User: 'root'
    condition: selection
";
    const IN_FULL: &str = "title: Checked in full
id: 22222222-2222-4222-8222-222222222222
status: test
level: medium
tags:
    - attack.t1021.004
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/ssh'
    condition: selection
";

    #[test]
    fn a_technique_only_a_rule_checked_in_part_names_is_not_drawn() {
        // A rule evaluated in part never matches some of what it looks for here; drawing its
        // technique as watched would claim coverage the program does not have.
        let state = |files: &[(&'static str, &'static str)], week: BTreeMap<String, i64>| {
            let rules = Rules::load(files);
            let mut l = all_arriving();
            l.matches_last_week = week;
            grid_of(&rules, Some(&l), &BTreeSet::new())
                .into_iter()
                .flat_map(|(_, s)| s)
                .filter(|(t, _)| *t == "T1021")
                .map(|(_, s)| s)
                .collect::<Vec<Square>>()
        };
        let part = state(&[("in-part.yml", IN_PART)], BTreeMap::new());
        assert!(part.is_empty(), "{part:?}");
        // What it matched on this Mac is drawn, as a match.
        let matched = BTreeMap::from([("11111111-1111-4111-8111-111111111111".to_string(), 1)]);
        let hit = state(&[("in-part.yml", IN_PART)], matched);
        assert!(
            !hit.is_empty() && hit.iter().all(|s| *s == Square::Matched),
            "{hit:?}"
        );
        let full = state(
            &[("in-part.yml", IN_PART), ("in-full.yml", IN_FULL)],
            BTreeMap::new(),
        );
        assert!(
            !full.is_empty() && full.iter().all(|s| *s == Square::Quiet),
            "{full:?}"
        );
    }

    #[test]
    fn a_match_is_tinted_in_three_steps_by_the_matches_of_the_rules_that_name_its_technique() {
        // The tint says how much matched, and the square's title says the number; each rule's
        // matches count once for a technique, whichever of its sub-techniques it names.
        assert_eq!(
            [step(1), step(2), step(9), step(10), step(5000)],
            ["s1", "s2", "s2", "s3", "s3"]
        );
        let rules = Rules::load(&[("in-part.yml", IN_PART), ("in-full.yml", IN_FULL)]);
        let mut l = all_arriving();
        l.matches_last_week = BTreeMap::from([
            ("11111111-1111-4111-8111-111111111111".to_string(), 3),
            ("22222222-2222-4222-8222-222222222222".to_string(), 8),
        ]);
        let (m, r) = answers(&rules, Some(&l));
        let rows = drawn(&m, &r);
        assert_eq!(matches_by_technique(&rows), BTreeMap::from([("T1021", 11)]));
        let (m, r) = answers(&rules, Some(&all_arriving()));
        assert!(matches_by_technique(&drawn(&m, &r)).is_empty());
    }

    #[test]
    fn a_rule_leads_only_to_a_finding_the_table_draws_and_its_square_is_raised_only_by_an_open_one()
    {
        // "Finding" links to a row of the findings table, which draws a finding open or with
        // its answer in force, so nothing leads to one whose answer has lapsed. A square in a
        // finding's colour says a finding of its rule is open.
        let r = v1::Rule {
            techniques_text: vec!["T1027.001".to_string()],
            ..rule("Invented", v1::Level::Medium)
        };
        let d = [Drawn {
            rule: &r,
            full: true,
            watching: true,
            week: 2,
        }];
        let listed =
            |id: &str, state: v1::FindingState, in_force: Option<bool>| v1::ListedFinding {
                finding: Some(v1::FindingRef {
                    id: id.to_string(),
                    rule: Some(r.name.clone()),
                    state: state as i32,
                    ..Default::default()
                }),
                answer: in_force.map(|in_force| v1::Answer {
                    in_force,
                    given_at: 5,
                    ..Default::default()
                }),
                ..Default::default()
            };
        let found = |f: Vec<v1::ListedFinding>| v1::Findings {
            findings: f,
            ..Default::default()
        };
        let drawn = |f: Vec<v1::ListedFinding>| {
            let (mut row, mut grid) = (String::new(), String::new());
            matched(&mut row, &d, &found(f.clone())).unwrap();
            cover(&mut grid, &d, &found(f)).unwrap();
            (row, grid)
        };
        let lapsed = || listed("lapsed", v1::FindingState::Expected, Some(false));
        let (row, grid) = drawn(vec![lapsed(), listed("open", v1::FindingState::Open, None)]);
        assert!(row.contains("<a href=\"#open\">Finding</a>"), "{row}");
        assert!(grid.contains("class=\"m look\" title="), "{grid}");
        let (row, grid) = drawn(vec![lapsed()]);
        assert!(row.contains("<span class=\"rs\">Counted</span>"), "{row}");
        assert!(!grid.contains("class=\"m look\" title="), "{grid}");
        let (row, grid) = drawn(vec![
            lapsed(),
            listed("seen", v1::FindingState::Seen, Some(true)),
        ]);
        assert!(row.contains("<a href=\"#answered-seen\">"), "{row}");
        assert!(!grid.contains("class=\"m look\" title="), "{grid}");
    }

    /// A rule as `immunity rules` gives one, of SigmaHQ's set or of a set that states no level.
    fn rule(title: &str, level: v1::Level) -> v1::Rule {
        let set = match level {
            v1::Level::NotStated => "Elastic's behaviour rules",
            _ => "SigmaHQ's rule set",
        };
        v1::Rule {
            name: format!("x:{title}"),
            id_text: title.to_string(),
            title_text: title.to_string(),
            level: level as i32,
            set: set.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn a_rule_title_is_data_escaped_in_an_element_of_its_own() {
        // A rule's title is its author's text. In the page it is escaped and set apart, never
        // markup and never mixed into the program's words.
        let rule = rule("<b>Padding</b> & \"co\"", v1::Level::Medium);
        let mut out = String::new();
        let row = Row {
            rule: &rule,
            count: 1_234,
            finding: None,
        };
        rule_row(&mut out, &row).unwrap();
        assert!(
            out.contains(
                "<span class=\"rt\"><bdi class=\"src\">&lt;b&gt;Padding&lt;/b&gt; &amp; &quot;co&quot;</bdi> (SigmaHQ&#39;s rule set)</span>"
            ),
            "{out}"
        );
        assert!(!out.contains("<b>"), "{out}");
        assert!(
            out.contains("<span class=\"rc\">1,234</span><span class=\"rs\">Counted</span>"),
            "{out}"
        );
    }

    #[test]
    fn a_rule_of_a_set_that_states_no_level_is_never_ranked_or_cut_by_severity() {
        // Twelve rules with a level and twelve of a set that states none matched. The cut by
        // severity is over the rules with a level only; the others are a group of their own
        // under its heading, with its own count and its own cut, by count, never hidden as the
        // least severe.
        let rules: Vec<v1::Rule> = (0..24)
            .map(|i| {
                let level = match i {
                    12.. => v1::Level::NotStated,
                    _ => [v1::Level::Medium, v1::Level::Low][i % 2],
                };
                rule(&format!("Invented {i:02}"), level)
            })
            .collect();
        // The rules with no level matched most, so a cut by count over all would show them.
        let mut rows: Vec<Row> = rules
            .iter()
            .enumerate()
            .map(|(i, rule)| Row {
                rule,
                count: if i < 12 { 1 } else { 100 + i as u64 },
                finding: None,
            })
            .collect();
        let mut out = String::new();
        matched_rows(&mut out, &mut rows).unwrap();
        let heading = out
            .find("<h4>Of a set that states no level</h4><span class=\"n\">12 rules, counted and not ranked by severity</span>")
            .expect("the group's heading");
        let shown = |range: std::ops::Range<usize>| {
            range
                .map(|i| out.find(&format!("Invented {i:02}</bdi> (")))
                .collect::<Vec<_>>()
        };
        let levelled = shown(0..12);
        let unlevelled = shown(12..24);
        // Ten with a level shown, the mediums first, all before the heading.
        assert_eq!(levelled.iter().flatten().count(), 10, "{out}");
        assert!(levelled.iter().flatten().all(|at| *at < heading), "{out}");
        assert!(levelled[0].is_some() && levelled[11].is_none(), "{out}");
        // Ten of the group shown after its heading, the most counted first.
        assert_eq!(unlevelled.iter().flatten().count(), 10, "{out}");
        assert!(unlevelled.iter().flatten().all(|at| *at > heading), "{out}");
        assert!(unlevelled[11].unwrap() < unlevelled[10].unwrap(), "{out}");
        assert!(unlevelled[0].is_none() && unlevelled[1].is_none(), "{out}");
        assert_eq!(
            shown_said(&rows),
            "12 rules with a level matched this week; the 10 most severe are shown · \
             12 rules of a set that states no level matched this week; the 10 counted most are shown · "
        );
    }

    #[test]
    fn a_rule_that_states_no_level_is_drawn_as_counted_and_says_so() {
        // A rule of a set that states no level shows that in the row, in the style of a rule
        // below high, and its matches are counted, never drawn as a finding.
        let rule = rule("Invented", v1::Level::NotStated);
        let mut out = String::new();
        let row = Row {
            rule: &rule,
            count: 3,
            finding: None,
        };
        rule_row(&mut out, &row).unwrap();
        assert!(
            out.contains("<bdi class=\"src\">Invented</bdi> (Elastic&#39;s behaviour rules)")
                && out.contains("<span class=\"rl\">no level stated</span>")
                && out.contains("<span class=\"rs\">Counted</span>"),
            "{out}"
        );
    }

    fn level(last_day: Tally) -> Level {
        Level {
            state: events::RUNNING.to_string(),
            read_at: 0,
            stored: (events::RUNNING.to_string(), 0),
            written: None,
            said_by: None,
            said: None,
            reason: None,
            version: None,
            since_check: Tally::default(),
            last_day,
            matches_last_day: BTreeMap::new(),
            matches_last_week: BTreeMap::new(),
            starts_by_hour: Series::default(),
            starts_by_minute: Series::default(),
            files: crate::events::Files::default(),
            arrivals: Default::default(),
            cap: None,
        }
    }

    #[test]
    fn rules_watching_now_is_the_status_s_number_leaving_out_a_rule_that_reads_what_does_not_arrive()
     {
        // "Rules watching now" is calm about each rule it counts. A rule that reads a field the
        // collector here does not keep watches nothing; the status leaves it out of its count,
        // and the page says the status's number.
        use crate::events::{Arrival, Arrivals};
        use crate::sigma::ELASTIC;
        // An invented rule taken in full about files written by a program it names by its
        // signature, which an earlier collector does not keep.
        let rules = Rules::load_as(
            &ELASTIC,
            &[(
                "signed.yml",
                Box::leak(
                    format!(
                        "title: Invented signed\nid: 00000000-0000-4000-8000-000000000001\nstatus: test\n\
                         level: high\nlogsource: {{\"product\": \"macos\", \"category\": \"file_event\"}}\n\
                         detection:\n  s1: {{\"process.code_signature.signing_id|cased\": [\"com.example\"]}}\n  condition: s1\n{}",
                        crate::sigma::testing::record_of(&ELASTIC, "\"high\"", "")
                    )
                    .into_boxed_str(),
                ),
            )],
        );
        let on = Arrival::Kept(Some(1));
        let drawn_as = |arrivals: Arrivals| -> (String, Option<u64>) {
            let l = Level {
                arrivals,
                ..all_arriving()
            };
            let r = crate::status::rules_now_of(&rules, Some(&l));
            let mut out = String::new();
            watching(&mut out, &r, &crate::events::message(&l)).unwrap();
            (out, r.watching_rules)
        };
        let number = |n: u64| format!("<span class=\"sv\" data-live=\"watching\">{n}</span>");
        let (all, counted) = drawn_as(Arrivals::from([on; 5]));
        assert_eq!(counted, Some(1));
        assert!(all.contains(&number(1)), "{all}");
        let not_kept = Arrivals::from([on, on, Arrival::NotKept, on, Arrival::NotKept]);
        let (earlier, counted) = drawn_as(not_kept);
        assert_eq!(counted, Some(0));
        assert!(earlier.contains(&number(0)), "{earlier}");
    }

    #[test]
    fn lost_reads_zero_only_when_every_start_of_the_day_was_read() {
        // "0 lost" is calm. A restart of the collector, a line that could not be read or an
        // hour deleted before it was read lose starts nobody counted: never zero, and the line
        // that says it is shown.
        let big = |t: Tally| {
            let mut out = String::new();
            lost(&mut out, &crate::events::message(&level(t))).unwrap();
            let hidden = out.contains("<p class=\"first\" data-live=\"lostline\" hidden>");
            let tag = "<span data-live=\"lost\">";
            let at = out.find(tag).unwrap() + tag.len();
            let said = out[at..at + out[at..].find('<').unwrap()].to_string();
            assert_eq!(hidden, said == "0", "{out}");
            said
        };
        assert_eq!(big(Tally::default()), "0");
        let restart = Tally {
            unknown_gaps: 1,
            ..Tally::default()
        };
        assert_eq!(big(restart), "some");
        let deleted = Tally {
            removed_unread: 1,
            ..Tally::default()
        };
        assert_eq!(big(deleted), "some");
        let both = Tally {
            lost: 1_204,
            unknown_gaps: 1,
            ..Tally::default()
        };
        assert_eq!(big(both), "1,204+");
        // Files the cap deleted after they were read lost nothing: neither a loss nor an
        // unknown one.
        let counted = Tally {
            lost: 12,
            removed_cap: 3,
            ..Tally::default()
        };
        assert_eq!(big(counted), "12");
        let capped = Tally {
            removed_cap: 3,
            ..Tally::default()
        };
        assert_eq!(big(capped), "0");
    }

    #[test]
    fn the_section_s_state_is_the_message_s_in_the_fixed_words_and_one_not_known_is_failed() {
        // The script reads the section's state as one of the fixed words: the message's state
        // as it is, and one this build does not know as `failed`, never as running.
        let of = |state: v1::CollectorState| {
            known_of(Some(&v1::EventLevel {
                state: state as i32,
                ..Default::default()
            }))
        };
        assert_eq!(of(v1::CollectorState::Running), events::RUNNING);
        assert_eq!(of(v1::CollectorState::NotInstalled), events::NOT_INSTALLED);
        assert_eq!(of(v1::CollectorState::Unspecified), events::FAILED);
        assert_eq!(known_of(None), "none");
    }

    #[test]
    fn the_bars_add_up_to_the_day_and_an_empty_hour_is_never_drawn_as_a_bar() {
        // The bars stand beside the count of the day: each says its hours and its count, and
        // an hour with no start is a line of the separator's colour, not a short bar that
        // reads as some.
        let mut counts = vec![0; events::HOURS];
        counts[0] = 1_500;
        counts[23] = 3;
        let svg = bars(&v1::Series {
            ends_at: 1_791_000_000,
            step_seconds: 3600,
            counts,
        });
        assert_eq!(svg.matches("<rect").count(), events::HOURS);
        assert_eq!(svg.matches("var(--bar)").count(), 2);
        assert_eq!(svg.matches("var(--sep)").count(), events::HOURS - 2);
        assert!(svg.contains("UTC: 1,500 program starts</title>"), "{svg}");
        assert!(svg.contains("UTC: 3 program starts</title>"), "{svg}");
        assert!(svg.contains("most in one hour: 1,500"), "{svg}");
    }

    /// JavaScriptCore's shell, which macOS ships.
    const JSC: &str =
        "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc";

    /// Runs the section's script over a stand-in for the page made while the level was
    /// `state`, with `live` as the file holds it, written `age` seconds ago, or no file. Returns
    /// the text the script left in each element it names, by name, and whether it is hidden.
    fn page_after(state: &str, live: Option<Value>, age: i64) -> Value {
        let stand_in = format!(
            r#"var window = globalThis;
var LIVE = {};
var made = {{}};
function el() {{
  return {{ textContent: "", hidden: false, style: {{}}, a: {{}},
    getAttribute: function (n) {{ return n in this.a ? this.a[n] : null; }},
    setAttribute: function (n, v) {{ this.a[n] = String(v); }},
    querySelector: function () {{ return null; }},
    querySelectorAll: function () {{ return []; }} }};
}}
var sec = el();
sec.a["data-state"] = "{state}";
sec.a["data-matched"] = "";
sec.querySelector = function (sel) {{
  var m = /data-live="([^"]+)"/.exec(sel);
  return m ? (made[m[1]] = made[m[1]] || el()) : null;
}};
sec.querySelectorAll = function (sel) {{
  var e = sec.querySelector(sel);
  return e ? [e] : [];
}};
var document = {{
  querySelectorAll: function () {{ return []; }}, addEventListener: function () {{}},
  getElementById: function (id) {{ return id === "as-it-happens" ? sec : null; }},
  createElement: function () {{ return {{ remove: function () {{}} }}; }},
  head: {{ appendChild: function (s) {{
    if (LIVE) {{ LIVE.written_at_seconds = Date.now() / 1000 - {age}; window.immunityLive = LIVE; }}
    LIVE ? s.onload() : s.onerror();
  }} }},
}};
function setInterval() {{}}
{SCRIPT}
var out = {{}};
for (var k in made) out[k] = {{ text: made[k].textContent, hidden: made[k].hidden }};
print(JSON.stringify(out));
"#,
            live.map_or("null".to_string(), |v| v.to_string()),
        );
        run_js(&stand_in)
    }

    /// Runs a script in JavaScriptCore's shell and returns the JSON it prints.
    fn run_js(stand_in: &str) -> Value {
        static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "immunity-happens-{}-{}.js",
            std::process::id(),
            RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::write(&path, stand_in).unwrap();
        let out = std::process::Command::new(JSC).arg(&path).output().unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn running_live() -> Value {
        let mut l = level(Tally {
            starts: 154_358,
            unknown_gaps: 2,
            ..Tally::default()
        });
        l.starts_by_hour = Series {
            ends_at: 1_791_000_000,
            step: 3600,
            counts: vec![0; events::HOURS],
        };
        live(Some(&l), 0)
    }

    #[test]
    fn the_page_says_how_fresh_its_numbers_are_and_that_it_is_not_updating_once_the_file_is_a_minute_old()
     {
        // A page that keeps showing numbers nobody updates would read as watched: once the
        // watcher's file is a minute old, or there is none, the page says so in its header.
        let fresh = page_after(events::RUNNING, Some(running_live()), 5);
        assert_eq!(fresh["said"]["text"], "updated 5 seconds ago", "{fresh}");
        assert_eq!(fresh["last_day"]["text"], "154,358", "{fresh}");
        assert_eq!(fresh["lost"]["text"], "some", "{fresh}");
        assert_eq!(fresh["lost-note"]["text"], "2 restarts", "{fresh}");
        // A loss that comes after the page was made shows the line that says it.
        assert_eq!(fresh["lostline"]["hidden"], false, "{fresh}");
        assert_eq!(fresh["week"]["text"], "0", "{fresh}");
        assert_eq!(fresh["moved"]["hidden"], true, "{fresh}");
        let old = page_after(events::RUNNING, Some(running_live()), 61);
        assert_eq!(old["said"]["text"], "not updating: no watcher is running");
        let within = page_after(events::RUNNING, Some(running_live()), 50);
        assert_eq!(within["said"]["text"], "updated 50 seconds ago");
        let none = page_after(events::RUNNING, None, 0);
        assert_eq!(none["said"]["text"], "not updating: no watcher is running");
        assert!(none.get("last_day").is_none(), "{none}");
    }

    #[test]
    fn a_page_whose_numbers_are_dated_ahead_of_the_clock_says_so_and_gives_them_no_age() {
        let ahead = page_after(events::RUNNING, Some(running_live()), -301);
        assert_eq!(
            ahead["said"]["text"],
            "updated at a time ahead of this Mac's clock"
        );
        let a_little = page_after(events::RUNNING, Some(running_live()), -300);
        assert_eq!(a_little["said"]["text"], "updated 0 seconds ago");
    }

    #[test]
    fn a_page_made_while_the_level_ran_never_shows_its_numbers_as_current_once_it_stopped() {
        // No false calm: the numbers of a running level stay on the page only beside the line
        // that says it no longer runs, and are not redrawn as if it did.
        let mut l = level(Tally::default());
        l.state = events::REFUSED.to_string();
        // Nor a count of file events checked, though the collector here records them.
        l.files.collected = true;
        l.files.last_day.files = 9;
        assert_eq!(
            live(Some(&l), 0)["file_events_last_day"],
            serde_json::Value::Null
        );
        let page = page_after(events::RUNNING, Some(live(Some(&l), 0)), 5);
        assert_eq!(
            page["moved"],
            serde_json::json!({ "text": "Program starts are refused by macOS now. The rest of this section is as the page was made; open it again from the app.", "hidden": false }),
            "{page}"
        );
        assert!(page.get("last_day").is_none(), "{page}");
    }

    #[test]
    fn the_file_for_an_open_page_holds_numbers_ids_of_shipped_rules_and_fixed_words_only() {
        // A browser runs what the file holds: a rule id the store holds that no shipped rule
        // has, or a state the program never writes, does not reach it.
        let mut l = level(Tally {
            starts: 7,
            lost: 3,
            ..Tally::default()
        });
        l.state = "<img src=x onerror=alert(1)>".to_string();
        l.matches_last_week = BTreeMap::from([
            (PADDING.to_string(), 2),
            ("</script><script>alert(1)//".to_string(), 1),
        ]);
        let v = live(Some(&l), 1_791_000_000);
        assert_eq!(v["state"], events::FAILED);
        assert_eq!(v["matches_last_week"], serde_json::json!({ PADDING: 2 }));
        assert_eq!(v["written_at_seconds"], 1_791_000_000);
        l.state = events::RUNNING.to_string();
        let v = live(Some(&l), 0);
        assert_eq!(
            (&v["state"], &v["state_words"]),
            (&serde_json::json!("running"), &serde_json::json!("on"))
        );
        assert_eq!(
            (&v["last_day"], &v["lost"]),
            (&serde_json::json!(7), &serde_json::json!("3"))
        );
        assert_eq!(
            live(None, 5),
            serde_json::json!({ "written_at_seconds": 5, "state": "none" })
        );
    }

    #[test]
    fn every_technique_has_one_sentence_of_mitres_description_with_no_markup_left() {
        // The pop-up says what a technique is in MITRE's words: one sentence for each technique
        // the file lists, and none of the markup of MITRE's text, a citation, a link or a tag,
        // which would read as noise. The ids, names and tactics are pinned by the test of the
        // squares drawn.
        let a = attack();
        assert!(a.about.keys().eq(a.names.keys()));
        for (id, s) in &a.about {
            let ends = s
                .char_indices()
                .filter(|(i, c)| {
                    ".!?".contains(*c) && s[i + 1..].chars().next().is_none_or(char::is_whitespace)
                })
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            assert_eq!(ends, [s.len() - 1], "{id}: {s}");
            assert!(s.starts_with(char::is_uppercase), "{id}: {s}");
            assert_eq!(
                s.split_whitespace().collect::<Vec<_>>().join(" "),
                *s,
                "{id}"
            );
            for markup in ["(Citation", "](", "<", ">", "`", "http"] {
                assert!(!s.contains(markup), "{id}: {s}");
            }
        }
    }

    #[test]
    fn a_square_carries_its_technique_and_state_as_escaped_data_and_a_description_stays_text() {
        // The pop-up reads a square's data and sets it as text. What the page carries is
        // escaped, so a description with characters that matter in HTML is never markup; the
        // title and the accessible name say the id, the name and the state without the script.
        let mut out = String::new();
        let about = "Adversaries may <script>alert(\"x\")</script> & 'run'.";
        square(
            &mut out,
            "hit s2",
            ("T1059", "Command & Scripting", about),
            "a rule for it matched this week, 3 matches",
            false,
        )
        .unwrap();
        let said = "T1059 Command &amp; Scripting: a rule for it matched this week, 3 matches";
        assert_eq!(
            out,
            format!(
                "<span class=\"m hit s2\" title=\"{said}\" role=\"img\" aria-label=\"{said}\" data-t=\"T1059\" data-n=\"Command &amp; Scripting\" data-d=\"Adversaries may &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &#39;run&#39;.\" data-s=\"a rule for it matched this week, 3 matches\"></span>"
            )
        );
        out.clear();
        square(&mut out, "look", ("T1", "N", "D."), "s", true).unwrap();
        assert!(out.ends_with("data-s=\"s\" data-now></span>"), "{out}");
        // MITRE's words are in the printer's form: a hidden character or a backslash is seen.
        out.clear();
        square(&mut out, "look", ("T1", "N\u{202e}", "D\\."), "s", false).unwrap();
        assert!(
            out.contains("data-n=\"N\\u{202e}\" data-d=\"D\\u{5c}.\""),
            "{out}"
        );
    }

    #[test]
    fn the_pop_up_sets_a_squares_data_as_text_never_over_the_square_and_inside_the_page() {
        // At phone width, a square at the right edge and one at the bottom of the window: the
        // pop-up shows its three lines as text, lies below the square or above it and never
        // over it, and stays inside the page's width. The square's title is taken off so no
        // second tooltip shows; a mouse leaving hides the pop-up, a touch leaves it up.
        let stand_in = format!(
            r#"var window = globalThis;
window.innerHeight = 800; window.scrollX = 0; window.scrollY = 100;
function el() {{
  var e = {{ a: {{}}, on: {{}}, style: {{}}, kids: [], hidden: false, textContent: "",
    offsetWidth: 320, offsetHeight: 80,
    appendChild: function (c) {{ this.kids.push(c); }},
    getAttribute: function (n) {{ return n in this.a ? this.a[n] : null; }},
    setAttribute: function (n, v) {{ this.a[n] = String(v); }},
    removeAttribute: function (n) {{ delete this.a[n]; }}, remove: function () {{}},
    matches: function (sel) {{ return sel === ".m[data-t]" && "data-t" in this.a; }},
    querySelector: function () {{ return null; }},
    querySelectorAll: function () {{ return []; }},
    addEventListener: function (t, f) {{ this.on[t] = f; }} }};
  Object.defineProperty(e, "innerHTML", {{ set: function () {{ throw "innerHTML"; }} }});
  return e;
}}
function sq(left, top) {{
  var s = el();
  s.a = {{ title: "T1 N: s", "data-t": "T1059", "data-n": "Command and Scripting Interpreter",
    "data-d": "Adversaries may <b>run</b> & stop.", "data-s": "watched, quiet" }};
  s.getBoundingClientRect = function () {{
    return {{ left: left, top: top, right: left + 12, bottom: top + 12 }};
  }};
  return s;
}}
var squares = [sq(360, 200), sq(8, 760)];
var grid = el();
grid.querySelectorAll = function () {{ return squares; }};
var sec = el();
sec.querySelector = function (s) {{ return s === ".tactics" ? grid : null; }};
var document = el();
document.getElementById = function () {{ return sec; }};
document.createElement = function () {{ return el(); }};
document.body = el();
document.head = {{ appendChild: function (s) {{ s.onerror(); }} }};
document.documentElement = {{ clientWidth: 375 }};
function setInterval() {{}}
{SCRIPT}
var tip = document.body.kids[0];
var out = [];
squares.forEach(function (s) {{
  grid.on.pointerover({{ target: s, pointerType: "mouse" }});
  out.push({{ square: s.getBoundingClientRect(), left: parseFloat(tip.style.left) - window.scrollX,
    top: parseFloat(tip.style.top) - window.scrollY, hidden: tip.hidden, title: s.getAttribute("title"),
    lines: tip.kids.map(function (k) {{ return k.textContent; }}) }});
}});
grid.on.pointerout({{ target: squares[1], pointerType: "touch" }});
var touch = tip.hidden;
grid.on.pointerout({{ target: squares[1], pointerType: "mouse" }});
print(JSON.stringify({{ shown: out, touch_hidden: touch, mouse_hidden: tip.hidden }}));
"#
        );
        let v = run_js(&stand_in);
        let (w, h) = (320.0, 80.0);
        for s in v["shown"].as_array().unwrap() {
            let f = |k: &str| s[k].as_f64().unwrap();
            let sq = |k: &str| s["square"][k].as_f64().unwrap();
            assert_eq!(s["hidden"], false, "{s}");
            assert_eq!(s["title"], Value::Null, "{s}");
            assert_eq!(
                s["lines"],
                serde_json::json!([
                    "T1059 Command and Scripting Interpreter",
                    "Adversaries may <b>run</b> & stop.",
                    "watched, quiet"
                ])
            );
            assert!(f("left") >= 0.0 && f("left") + w <= 375.0, "{s}");
            let apart = f("top") >= sq("bottom") || f("top") + h <= sq("top");
            assert!(apart, "{s}");
        }
        // The square near the window's bottom has its pop-up above it.
        assert!(v["shown"][1]["top"].as_f64().unwrap() < 760.0, "{v}");
        assert_eq!(
            (&v["touch_hidden"], &v["mouse_hidden"]),
            (&false.into(), &true.into())
        );
    }

    #[test]
    fn the_copy_button_is_shown_and_copies_the_command_beside_it_with_or_without_a_clipboard() {
        // A page opened as a file may have no clipboard: the command is then selected and
        // copied, and when that fails too it stays selected for Cmd+C and the button never says
        // "Copied". With a clipboard, the text beside the button is what is written.
        let stand_in = format!(
            r#"var window = globalThis;
var cls = {{}};
var cmd = {{ textContent: "immunity finding f0 --json" }};
var b = {{ hidden: true, title: "", a: {{}}, previousElementSibling: cmd,
  setAttribute: function (n, v) {{ this.a[n] = v; }},
  classList: {{ add: function (c) {{ cls[c] = 1; }}, remove: function (c) {{ delete cls[c]; }} }},
  closest: function () {{ return b; }} }};
var on, selected = null, copies = 0, works = false, written = [];
var navigator = {{}};
var document = {{
  querySelectorAll: function () {{ return [b]; }},
  addEventListener: function (t, f) {{ on = f; }},
  getElementById: function () {{ return null; }},
  createRange: function () {{ return {{ selectNodeContents: function (n) {{ this.n = n; }} }}; }},
  execCommand: function () {{ copies++; return works; }} }};
window.getSelection = function () {{
  return {{ removeAllRanges: function () {{ selected = null; }}, addRange: function (r) {{ selected = r.n; }} }};
}};
function setTimeout() {{}}
{SCRIPT}
var out = {{ shown: !b.hidden }};
on({{ target: b }});
out.failed = {{ selected: selected === cmd, copies: copies, said: b.title }};
works = true;
on({{ target: b }});
out.copied = {{ selected: selected, said: b.title, label: b.a["aria-label"], done: !!cls.done }};
navigator.clipboard = {{ writeText: function (t) {{ written.push(t); return {{ then: function (ok) {{ ok(); }} }}; }} }};
on({{ target: b }});
out.written = written;
print(JSON.stringify(out));
"#
        );
        let v = run_js(&stand_in);
        assert_eq!(
            v,
            serde_json::json!({
                "shown": true,
                "failed": { "selected": true, "copies": 1, "said": "" },
                "copied": { "selected": null, "said": "Copied", "label": "Copied", "done": true },
                "written": ["immunity finding f0 --json"],
            })
        );
    }
}
