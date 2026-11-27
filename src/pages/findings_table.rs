//! The table of findings on the summary, drawn from what `immunity findings` answers and, for
//! each finding a row opens, what `immunity finding <id>` answers (`view::Answers`): nothing here
//! reads the store or decides again what the messages say. A finding of the core and the
//! response layer's own finding about the same rule and thing are one row, joined by what the
//! messages name: the rule a `verdict.suspicious` finding's verdicts were about
//! (`VerdictGiven.rule`) and the thing (`about_text`). Findings of one rule about one thing, a
//! package in several projects or a folder of hooks, are one row by one key (`Key`), each on a
//! line of its own with its id. Every finding open or answered is in exactly one row. The tabs
//! count findings as the status does, each finding of a pair or a row of several one.
//! Text from the Mac or a source in a row is printed through `secrets::Name` and
//! `secrets::Said`.

use super::{COPY, capital};
use crate::contract::v1;
use crate::secrets::{Name, Said};
use crate::view::{self, Answers, counted, esc};
use std::error::Error;
use std::fmt::Write;

/// At most this many things that need a look are shown in full, so the summary stays small.
const ITEMS_SHOWN: usize = 100;

/// A finding as the table takes it: as the list gives it, its reference, and whether it is open,
/// else answered with its answer in force. Any other finding, cleared or no longer hidden by an
/// answer while not open, is not in the table.
#[derive(Clone, Copy)]
struct Listed<'a> {
    l: &'a v1::ListedFinding,
    r: &'a v1::FindingRef,
    open: bool,
}

/// Whether a finding in this state is open: any state but expected, seen and cleared, so a state
/// the reader does not know is read as open (`common.proto`). One predicate for every page.
pub(crate) fn is_open(state: i32) -> bool {
    use v1::FindingState as S;
    !matches!(S::try_from(state), Ok(S::Expected | S::Seen | S::Cleared))
}

impl<'a> Listed<'a> {
    fn of(l: &'a v1::ListedFinding) -> Option<Listed<'a>> {
        let r = l.finding.as_ref()?;
        let open = is_open(r.state);
        let in_force = l.answer.as_ref().is_some_and(|a| a.in_force);
        (open || in_force).then_some(Listed { l, r, open })
    }

    /// Its id on the page: as it is while open, and after `answered-` while answered.
    fn anchor(&self) -> String {
        match self.open {
            true => esc(&self.r.id),
            false => format!("answered-{}", esc(&self.r.id)),
        }
    }
}

/// One row of the table: one thing. Its finding, the response layer's own findings about the same
/// thing, and the other findings with its key (`Key`) drawn in it.
struct FindingRow<'a> {
    item: Listed<'a>,
    under: Vec<Listed<'a>>,
    /// The other findings with the item's key, none with a verdict or a pair: each is drawn in
    /// the row on a line of its own, by its id.
    siblings: Vec<Listed<'a>>,
}

/// What joins findings into one row, the one rule for every kind of finding: the same rule, about
/// the same thing, in the same state, as severe, as sure and as urgent, and, once answered, with
/// the same answer, so what the row's summary says of one finding it says truly of each. The
/// thing is the folder of a group the core names (`ListedFinding.group`, one rule, machine,
/// change and folder: a folder of git hooks), or a package by its ecosystem and name, its source
/// said in the name (`view::component_name`), with the releases the list gives. A finding with
/// neither is a row of its own. So is one the response layer gave a word on, and one with the
/// response layer's own finding inside its row: the summary says that word, and it would stand
/// for findings it was not said of. The key decides only what is drawn together: every finding
/// keeps its id, its line in the row and its count in the tabs.
#[derive(PartialEq, Eq, Hash)]
struct Key<'a> {
    rule: Option<&'a str>,
    thing: Thing<'a>,
    state: i32,
    severity: Option<i32>,
    confidence: Option<i32>,
    urgent: bool,
    /// Which answer, how it came and until when, for a finding not open.
    answer: Option<(i32, i32, Option<i64>)>,
}

/// The thing of a key: a folder by its group, or a package by ecosystem, name and releases.
#[derive(PartialEq, Eq, Hash)]
enum Thing<'a> {
    Folder(&'a str),
    Package(&'a str, &'a str, &'a [String]),
}

impl<'a> FindingRow<'a> {
    /// Its key, `None` for a row that is joined with no other.
    fn key(&self) -> Option<Key<'a>> {
        let (l, r) = (self.item.l, self.item.r);
        if !self.under.is_empty() || verdict_word(l).is_some() {
            return None;
        }
        let thing = match (&l.group, &l.package_text) {
            (Some(group), _) => Thing::Folder(group),
            (None, Some(_)) => {
                let (ecosystem, name) = view::component_name(&r.about_text);
                Thing::Package(ecosystem, name, &l.releases_text)
            }
            (None, None) => return None,
        };
        Some(Key {
            rule: r.rule.as_deref(),
            thing,
            state: r.state,
            severity: r.severity,
            confidence: r.confidence,
            urgent: r.urgent,
            answer: (l.answer.as_ref())
                .filter(|_| !self.item.open)
                .map(|a| (a.given, a.via, a.until_at)),
        })
    }

    /// The findings drawn on lines of their own: the item and the others with its key.
    fn members(&self) -> Vec<Listed<'a>> {
        std::iter::once(self.item)
            .chain(self.siblings.iter().copied())
            .collect()
    }
}

impl FindingRow<'_> {
    /// How many findings the row holds.
    fn weight(&self) -> usize {
        1 + self.siblings.len() + self.under.len()
    }

    /// The row is in Open while any finding in it is open, and in Answered while any is
    /// answered: a verdict never takes a finding out of Open.
    fn open(&self) -> bool {
        self.item.open || self.under.iter().any(|u| u.open)
    }

    fn answered(&self) -> bool {
        !self.item.open || self.under.iter().any(|u| !u.open)
    }

    /// It needs the person now: an open finding in it, the core's or the response layer's,
    /// is one Immunity Core marks urgent.
    fn urgent(&self) -> bool {
        let urgent = |f: &Listed| f.open && f.r.urgent;
        urgent(&self.item) || self.under.iter().any(urgent)
    }
}

/// The rule a finding of `verdict.suspicious` is about, by the finding's id.
type Subject<'s> = dyn Fn(&str) -> Result<Option<String>, Box<dyn Error>> + 's;

/// The rows, open first in the list's order, then the answered, the latest answer first. A
/// finding of `verdict.suspicious` is drawn in the row of the core's finding of the rule its
/// verdicts were about and of the same thing, once, and is not a row of its own; one with no
/// such partner is a row of its own, so every finding is in exactly one row. `subject` gives
/// that rule for a finding of `verdict.suspicious`.
fn finding_rows<'a>(
    all: &[Listed<'a>],
    subject: &Subject,
) -> Result<Vec<FindingRow<'a>>, Box<dyn Error>> {
    let verdict = |f: &Listed| f.r.rule.as_deref() == Some(crate::verdict::RULE);
    let mut nested = std::collections::BTreeSet::new();
    let mut under: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
    for (k, own) in all.iter().enumerate().filter(|(_, f)| verdict(f)) {
        let Some(rule) = subject(&own.r.id)? else {
            continue;
        };
        // Never a finding of the response layer as the core's: one about the verdict rule would
        // otherwise pair with itself and be folded out of sight.
        let partner = all.iter().position(|core| {
            !verdict(core)
                && core.r.rule.as_deref() == Some(rule.as_str())
                && core.r.about_text == own.r.about_text
        });
        if let Some(n) = partner {
            nested.insert(k);
            under.entry(n).or_default().push(k);
        }
    }
    let rows = (all.iter().enumerate())
        .filter(|(n, _)| !nested.contains(n))
        .map(|(n, f)| FindingRow {
            item: *f,
            under: (under.get(&n).into_iter().flatten())
                .map(|k| all[*k])
                .collect(),
            siblings: Vec::new(),
        });
    // A row with the key of an earlier row goes into it, at the earlier row's place; a row with
    // no key goes into none, so every finding stays in exactly one row.
    let mut out: Vec<FindingRow> = Vec::new();
    let mut at: std::collections::HashMap<Key, usize> = Default::default();
    for row in rows {
        match row.key() {
            Some(key) => match at.get(&key) {
                Some(&n) => out[n].siblings.push(row.item),
                None => {
                    at.insert(key, out.len());
                    out.push(row);
                }
            },
            None => out.push(row),
        }
    }
    Ok(out)
}

/// The findings as a table with three tabs, Open, Answered and All, each with its count of
/// findings, a pair two, as the status counts them. The tabs are links within the page, and the
/// stylesheet shows the rows of the one in the address (`:target`), Open when none is; a browser
/// that cannot select by what an element holds shows every row, so nothing is hidden by a
/// browser's age. The open rows are in two groups, as the panel has them: what needs the person
/// now, then what is to look at; then the answered. Each row opens in place to its facts and who
/// said what.
pub(super) fn table(out: &mut String, a: &Answers, now: i64) -> Result<(), Box<dyn Error>> {
    let mut listed: Vec<Listed> = a.findings.findings.iter().filter_map(Listed::of).collect();
    let at = |f: &Listed| f.l.answer.as_ref().map_or(0, |a| a.given_at);
    listed.sort_by(|x, y| {
        (y.open.cmp(&x.open)).then_with(|| match x.open || y.open {
            true => std::cmp::Ordering::Equal,
            false => at(y).cmp(&at(x)).then_with(|| x.r.id.cmp(&y.r.id)),
        })
    });
    let subject = |id: &str| -> Result<Option<String>, Box<dyn Error>> {
        use v1::evidence::Body;
        Ok((a.finding)(id)?.and_then(|f| match f.evidence?.body? {
            Body::VerdictGiven(v) => Some(v.rule),
            _ => None,
        }))
    };
    let rows = finding_rows(&listed, &subject)?;
    let open = listed.iter().filter(|f| f.open).count();
    let answered = listed.len() - open;
    writeln!(
        out,
        "<section id=\"findings\" class=\"findings\">\n<div class=\"wsh\"><h2>Findings</h2><nav class=\"tabs\" aria-label=\"Findings\"><a id=\"open\" href=\"#open\">Open <span class=\"tn\">{}</span></a><a id=\"answered\" href=\"#answered\">Answered <span class=\"tn\">{}</span></a><a id=\"all\" href=\"#all\">All <span class=\"tn\">{}</span></a></nav></div>",
        counted(open as i64, "", "").trim_end(),
        counted(answered as i64, "", "").trim_end(),
        counted(listed.len() as i64, "", "").trim_end(),
    )?;
    if open == 0 {
        out.push_str("<p class=\"empty open\">Nothing is open. A change in what is watched shows here when it is found.</p>\n");
    }
    if answered == 0 {
        out.push_str("<p class=\"empty answered\">Nothing is marked seen or expected now.</p>\n");
    }
    let (now_rows, rest): (Vec<&FindingRow>, Vec<&FindingRow>) =
        rows.iter().partition(|r| r.urgent());
    let (look, done): (Vec<&FindingRow>, Vec<&FindingRow>) =
        rest.into_iter().partition(|r| r.open());
    // The open rows drawn, the urgent first, and the answered, each cut at `ITEMS_SHOWN`.
    let open_cut = now_rows.len().min(ITEMS_SHOWN);
    let look_cut = look.len().min(ITEMS_SHOWN - open_cut);
    for (group, class, rows) in [
        // The one place on the page in the colour of what needs the person now.
        ("Needs you now", "open now", &now_rows[..open_cut]),
        ("To look at", "open", &look[..look_cut]),
        ("Answered", "answered", &done[..done.len().min(ITEMS_SHOWN)]),
    ] {
        if rows.is_empty() {
            continue;
        }
        writeln!(out, "<p class=\"fg {class}\">{group}</p>")?;
        for row in rows {
            finding_row(out, a, row, now)?;
        }
    }
    // What is not drawn, in findings as the tabs count them.
    let weight = |rows: &[&FindingRow]| rows.iter().map(|r| r.weight()).sum::<usize>();
    let urgent = weight(&now_rows[open_cut..]);
    let hidden = urgent + weight(&look[look_cut..]);
    if hidden > 0 {
        // Urgent ones come first, so the rest are the mildest unless urgent ones overflow.
        let which = match urgent {
            0 => "the mildest".to_string(),
            u => format!("{} of them urgent", counted(u as i64, "", "").trim_end()),
        };
        writeln!(
            out,
            "<p class=\"meta more open\">{} more, {which}; <span class=\"mono\">immunity findings</span> lists them.</p>",
            counted(hidden as i64, "", "").trim_end()
        )?;
    }
    let answered_hidden = weight(&done[done.len().min(ITEMS_SHOWN)..]);
    if answered_hidden > 0 {
        writeln!(
            out,
            "<p class=\"meta more answered\">{} more answered; <span class=\"mono\">immunity findings --all</span> lists them.</p>",
            counted(answered_hidden as i64, "", "").trim_end()
        )?;
    }
    out.push_str("</section>\n");
    Ok(())
}

/// The response layer's verdict as one word: suspicious when any of its verdicts is, harmless
/// when every one is harmless; `None` with no verdict.
fn verdict_word(l: &v1::ListedFinding) -> Option<&'static str> {
    let v = l.verdicts.as_ref()?;
    let rule = l.finding.as_ref().and_then(|r| r.rule.as_deref());
    if rule == Some(crate::verdict::RULE) || v.suspicious > 0 {
        Some("Suspicious")
    } else if v.total > 0 {
        Some("Harmless")
    } else {
        None
    }
}

/// A name from the Mac as data, in an element of its own (`Name::html`).
fn named(s: &str) -> String {
    format!("<span class=\"mono\">{}</span>", Name::given(s).html())
}

/// The thing a finding is about, as HTML: in the program's words for a finding whose thing no
/// name from the Mac says, the item of places read for the first time; else the package and its
/// releases, the program or file a rule matched, else where it is, each a name.
fn thing_of(l: &v1::ListedFinding, f: Option<&v1::Finding>) -> String {
    if let Some(thing) = &l.thing {
        return esc(thing);
    }
    let name = |s: &str| Name::given(s).html();
    use v1::evidence::Body;
    let events: &[v1::Event] = match f.and_then(|f| f.evidence.as_ref()?.body.as_ref()) {
        Some(Body::VulnerablePackage(p)) => {
            if let Some(package) = &p.package_text {
                let releases: Vec<String> =
                    p.releases.iter().map(|r| name(&r.version_text)).collect();
                return match releases.is_empty() {
                    true => name(package),
                    false => format!(
                        "{} <span class=\"v\">{}</span>",
                        name(package),
                        releases.join(", ")
                    ),
                };
            }
            &[]
        }
        Some(Body::PublishedRuleMatched(p)) => &p.events,
        Some(Body::VerdictGiven(v)) => &v.events,
        _ => &[],
    };
    use v1::event::Body as E;
    match events.first().and_then(|e| e.body.as_ref()) {
        Some(E::ProgramStart(s)) => {
            if let Some(p) = &s.process {
                return name(&p.executable_text);
            }
        }
        Some(E::FileEvent(e)) => return name(&e.path_text),
        None => {}
    }
    let about = l.finding.as_ref().map_or("", |r| r.about_text.as_str());
    name(
        Some(l.where_text.as_str())
            .filter(|w| !w.is_empty())
            .unwrap_or(about),
    )
}

/// One row, one thing: the thing as data; what happened to it, with the response layer's word and
/// the answer under it; in how many places it is; and when it was last seen. A row of one finding
/// opens to its facts and voices and the command that reads it. A row of several opens to what
/// every one of them says alike, said once, then each finding on a line of its own (`group_body`).
fn finding_row(
    out: &mut String,
    a: &Answers,
    row: &FindingRow,
    now: i64,
) -> Result<(), Box<dyn Error>> {
    let i = row.item;
    let members = row.members();
    let wholes = (members.iter())
        .map(|m| (a.finding)(&m.r.id))
        .collect::<Result<Vec<_>, _>>()?;
    // What happened, in the words a person reads: the kind and the change for a place that
    // changed, the same as the app's; else the rule's short title.
    let kind = match i.l.change {
        Some(change) => format!(
            "{} · {}",
            i.l.kind_title,
            crate::finding_text::change_said(change)
        ),
        None if !i.l.short_title.is_empty() => i.l.short_title.clone(),
        None => i.l.kind_title.clone(),
    };
    // In how many places: projects for a package, files for a folder that holds several.
    let n = members.len() as i64;
    let places = match (&i.l.package_text, &i.l.folder_text) {
        (Some(_), _) => counted(n, "project", "projects"),
        (None, Some(_)) if n > 1 => counted(n, "file", "files"),
        _ => String::new(),
    };
    // A row of several in one folder is the folder.
    let thing = match i.l.folder_text.as_deref().filter(|_| n > 1) {
        Some(folder) => Name::given(folder).html(),
        None => thing_of(i.l, wholes[0].as_ref()),
    };
    let verdict = verdict_word(i.l).map_or(String::new(), |w| {
        format!("<span class=\"fv\"><span class=\"src\">Response layer: </span>{w}</span>")
    });
    let answer = i.l.answer.as_ref().filter(|_| !i.open).map(|a| {
        let said = match a.until_at {
            Some(u) => format!("expected until {}", view::when(u, now)),
            None => "seen".to_string(),
        };
        format!(
            "<span class=\"ans\">Answered: {said} {}</span>",
            esc(crate::finding_text::given_by(a.via))
        )
    });
    let last = (members.iter().map(|m| m.l.last_seen_at).max()).unwrap_or(i.l.last_seen_at);
    writeln!(
        out,
        "<details class=\"fr{}{}{}{}\" id=\"{}\">\n<summary><span class=\"fw\">{thing}</span><span class=\"fk\">{}{verdict}{}</span><span class=\"fc\">{places}</span><span class=\"fs\">{}</span><span class=\"fch\" aria-hidden=\"true\"></span></summary>\n<div class=\"fx\">",
        if row.open() { " open" } else { "" },
        if row.answered() { " answered" } else { "" },
        if row.urgent() { " urgent" } else { "" },
        // The mark of the response layer's word, the word's own colour (`.fr.suspicious .fv`).
        match verdict_word(i.l) {
            Some("Suspicious") => " suspicious",
            Some("Harmless") => " harmless",
            _ => "",
        },
        i.anchor(),
        esc(&kind),
        answer.unwrap_or_default(),
        view::when(last, now),
    )?;
    match members.len() {
        1 => finding_body(out, i, wholes[0].as_ref(), now)?,
        _ => group_body(out, &members, &wholes, now)?,
    }
    for c in &row.under {
        writeln!(
            out,
            "<div class=\"also\" id=\"{}\">\n<p class=\"wsh2\">The response layer's own finding about it</p>",
            c.anchor()
        )?;
        let whole = (a.finding)(&c.r.id)?;
        finding_body(out, *c, whole.as_ref(), now)?;
        out.push_str("</div>\n");
    }
    out.push_str("</div>\n</details>\n");
    Ok(())
}

/// A fact of an opened row: its term and its value, already safe.
type Fact = (&'static str, String);

/// What one finding says, but for where it is: its facts, the evidence as `immunity finding <id>`
/// gives it, then who said what, each voice named: the rule's authors, the response layer, the
/// person's answer, Immunity Core's own words, and what to do.
fn said(i: Listed, f: Option<&v1::Finding>, now: i64) -> (Vec<Fact>, Vec<Voice>) {
    let mut facts: Vec<Fact> = Vec::new();
    // A finding of a rule this build does not have names the rule as the store keeps it: the
    // one thing beside where it is that says what found it.
    if i.l.kind == crate::findings::KEPT_KIND {
        facts.push(("Rule", named(i.r.rule.as_deref().unwrap_or_default())));
    }
    let (mut evidenced, mut voices) = (Vec::new(), Vec::new());
    let set_out = f.is_some_and(|f| evidence(f, &mut evidenced, &mut voices, now));
    // What the source said, as data beside the sentences, cut as it is printed; said once, by the
    // evidence, where the evidence sets out every part of it.
    if let Some(value) = f.and_then(|f| f.value_text.as_deref()).filter(|_| !set_out) {
        let said = Said::of(&crate::contract::unescape(value)).html();
        facts.push(("Source said", format!("<span class=\"said\">{said}</span>")));
    }
    facts.extend(evidenced);
    if let Some(t) = f.and_then(|f| f.technique_text.as_deref()) {
        facts.push(("ATT&amp;CK", named(t)));
    }
    // A release declared where the finding is, is said once, as where it is.
    let here = named(&i.l.where_text);
    facts.retain(|(k, v)| !(*k == "Declared at" && *v == here));
    voices.push(Voice {
        name: "Immunity Core".to_string(),
        said: esc(f.map_or(&i.l.title, |f| &f.title)),
        detail: esc(f.map_or("", |f| &f.meaning)),
        quote: None,
    });
    voices.push(Voice {
        name: "What to do".to_string(),
        said: format!(
            "<span class=\"advice\">{}</span>",
            esc(f.map_or("", |f| &f.advice))
        ),
        detail: String::new(),
        quote: None,
    });
    (facts, voices)
}

/// What one finding says in an opened row: on the left where it is, then its facts; on the right
/// who said what. Under them, when it was seen and the command an agent reads it with.
fn finding_body(
    out: &mut String,
    i: Listed,
    f: Option<&v1::Finding>,
    now: i64,
) -> Result<(), Box<dyn Error>> {
    let (mut facts, voices) = said(i, f, now);
    facts.insert(0, ("Where", named(&i.l.where_text)));
    out.push_str("<div>");
    dl(out, &facts);
    out.push_str("</div>\n<div><p class=\"wsh2\">Who said what</p>");
    voices_of(out, voices.iter())?;
    out.push_str("</div>\n");
    writeln!(
        out,
        "<div class=\"fxb\"><span>{}</span><span>For your agent {}</span></div>",
        seen(i.l.first_seen_at, i.l.last_seen_at, now),
        command(&i.r.id)
    )?;
    Ok(())
}

/// What the findings of a row of several say. What every one of them says alike, once: its facts
/// on the left, its voices on the right. Then each finding on a line of its own, every one, in the
/// order of where they are, so a person finds a project or a file: where it is, the command that
/// reads it by its id, and what it says that the others do not, its answer through an agent or its
/// time to expect among them. Under them, when the first was first seen and the last last seen.
fn group_body(
    out: &mut String,
    members: &[Listed],
    wholes: &[Option<v1::Finding>],
    now: i64,
) -> Result<(), Box<dyn Error>> {
    let all: Vec<(Vec<Fact>, Vec<Voice>)> = (members.iter().zip(wholes))
        .map(|(m, f)| said(*m, f.as_ref(), now))
        .collect();
    let facts: Vec<&Fact> = (all[0].0.iter())
        .filter(|f| all.iter().all(|(of, _)| of.contains(f)))
        .collect();
    let voices: Vec<&Voice> = (all[0].1.iter())
        .filter(|v| all.iter().all(|(_, of)| of.contains(v)))
        .collect();
    out.push_str("<div>");
    dl(out, facts.iter().copied());
    out.push_str("</div>\n<div><p class=\"wsh2\">Who said what</p>");
    voices_of(out, voices.iter().copied())?;
    out.push_str("</div>\n");
    let (one, many) = match members[0].l.package_text {
        Some(_) => ("project", "projects"),
        None => ("file", "files"),
    };
    writeln!(
        out,
        "<div class=\"in\"><p class=\"wsh2\">In {}, one finding each</p>\n<ul>",
        counted(members.len() as i64, one, many)
    )?;
    let place = |m: &Listed<'_>| -> String {
        let place = Some(m.l.where_text.as_str()).filter(|w| !w.is_empty());
        place.unwrap_or(&m.r.about_text).to_string()
    };
    let mut lines: Vec<_> = members.iter().zip(&all).collect();
    lines.sort_by_key(|(m, _)| (place(m), m.r.id.as_str()));
    for (m, (own_facts, own_voices)) in lines {
        // The row's own finding is reached by the row's id.
        let id = match m.r.id == members[0].r.id {
            true => String::new(),
            false => format!(" id=\"{}\"", m.anchor()),
        };
        let place = place(m);
        write!(
            out,
            "<li{id}><span class=\"p\">{}</span>{}",
            Name::given(&place).html(),
            command(&m.r.id)
        )?;
        let own_facts: Vec<&Fact> = (own_facts.iter()).filter(|f| !facts.contains(f)).collect();
        let own_voices: Vec<&Voice> = (own_voices.iter())
            .filter(|v| !voices.contains(v))
            .collect();
        if !own_facts.is_empty() || !own_voices.is_empty() {
            out.push_str("<div class=\"own\">");
            dl(out, own_facts.iter().copied());
            if !own_voices.is_empty() {
                voices_of(out, own_voices.iter().copied())?;
            }
            out.push_str("</div>");
        }
        out.push_str("</li>\n");
    }
    out.push_str("</ul></div>\n");
    let first = members.iter().map(|m| m.l.first_seen_at).min();
    let last = members.iter().map(|m| m.l.last_seen_at).max();
    writeln!(
        out,
        "<div class=\"fxb\"><span>{}</span></div>",
        seen(first.unwrap_or_default(), last.unwrap_or_default(), now)
    )?;
    Ok(())
}

/// When a finding, or the findings of a row, were seen: the first and the last time, or the one.
fn seen(first: i64, last: i64, now: i64) -> String {
    match first != last {
        true => format!(
            "First seen {} · last seen {}",
            view::when(first, now),
            view::when(last, now)
        ),
        false => format!("Seen {}", view::when(last, now)),
    }
}

/// The command an agent reads a finding with, escaped, and the fixed copy button after it, the
/// two never wrapped apart.
fn command(id: &str) -> String {
    format!(
        "<span class=\"cmd\"><span class=\"mono\">{}</span>{COPY}</span>",
        esc(&format!("immunity finding {id} --json"))
    )
}

/// Voices as "Who said what" draws them: each its name, what it said, a quieter line, and a
/// quote of its own words when it has one.
fn voices_of<'v>(out: &mut String, voices: impl Iterator<Item = &'v Voice>) -> std::fmt::Result {
    out.push_str("<div class=\"voices\">");
    for v in voices {
        write!(
            out,
            "<div class=\"voice\"><div class=\"vn\">{}</div><div class=\"vs\">{}</div>",
            v.name, v.said
        )?;
        if !v.detail.is_empty() {
            write!(out, "<div class=\"vd\">{}</div>", v.detail)?;
        }
        if let Some(q) = &v.quote {
            write!(
                out,
                "\n<blockquote class=\"quote\">{}</blockquote>\n",
                Said::given(q).html()
            )?;
        }
        out.push_str("</div>");
    }
    out.push_str("</div>");
    Ok(())
}

/// One voice of "Who said what": who, what they said and a quieter line, all safe HTML, and a
/// quote of their own words, cut as the message gives it, printed when it is written. Two voices
/// are alike when every part is (`group_body`).
#[derive(PartialEq)]
struct Voice {
    name: String,
    said: String,
    detail: String,
    quote: Option<String>,
}

/// What a source said as data, as a field of the message gives it cut, in an element of its own.
fn said_data(s: &str) -> String {
    format!("<span class=\"mono\">{}</span>", Said::given(s).html())
}

/// A number of the core's as data.
fn number(n: impl std::fmt::Display) -> String {
    format!("<span class=\"mono\">{n}</span>")
}

/// Arguments as they come cut, each apart.
fn arguments(args: &[String]) -> String {
    let args: Vec<String> = args
        .iter()
        .map(|a| format!("<span class=\"arg\">{}</span>", Said::given(a).html()))
        .collect();
    format!("<span class=\"mono\">{}</span>", args.join(" "))
}

/// One event a rule matched: for a program start its program, each argument apart, its folder
/// and the program that started it; for a file event the file, what was done, from where and by
/// which program. Arguments come cut, as `immunity finding` prints them (`matches::event_cut`).
fn event_facts(e: &v1::Event, now: i64) -> Vec<(&'static str, String)> {
    use v1::event::Body;
    let mut facts = Vec::new();
    match e.body.as_ref() {
        Some(Body::ProgramStart(s)) => {
            if let Some(at) = s.happened_at {
                facts.push(("When", view::when(at, now)));
            }
            if let Some(p) = &s.process {
                facts.push(("Program", named(&p.executable_text)));
            }
            if !s.args_text.is_empty() {
                facts.push(("Arguments", arguments(&s.args_text)));
            }
            if let Some(wd) = &s.working_directory_text {
                facts.push(("Folder", named(wd)));
            }
            if let Some(p) = &s.instigator {
                facts.push(("Started by", named(&p.executable_text)));
            }
        }
        Some(Body::FileEvent(f)) => {
            if let Some(at) = f.happened_at {
                facts.push(("When", view::when(at, now)));
            }
            facts.push(("File", named(&f.path_text)));
            let action = match v1::FileAction::try_from(f.action) {
                Ok(v1::FileAction::Create) => "created",
                Ok(v1::FileAction::Rename) => "renamed",
                _ => "not known",
            };
            facts.push(("Done", action.to_string()));
            if let Some(from) = &f.source_text {
                facts.push(("From", named(from)));
            }
            if let Some(p) = &f.instigator {
                facts.push(("By", named(&p.executable_text)));
            }
        }
        None => {}
    }
    facts
}

/// Facts as a list of terms and values; each value is already safe.
fn dl<'f>(out: &mut String, facts: impl IntoIterator<Item = &'f Fact>) {
    let mut facts = facts.into_iter().peekable();
    if facts.peek().is_none() {
        return;
    }
    out.push_str("<dl class=\"facts\">");
    for (k, v) in facts {
        let _ = write!(out, "<dt>{k}</dt><dd>{v}</dd>");
    }
    out.push_str("</dl>\n");
}

/// A process a sample saw, as `DetachedProcess` gives it, each fact only where the finding has
/// it.
fn process_facts(p: &v1::DetachedProcess, facts: &mut Vec<(&str, String)>, now: i64) {
    if let Some(pid) = p.pid {
        facts.push(("Process id", number(pid)));
    }
    if let Some(start) = p.start_micros {
        facts.push(("Started", view::when(start.div_euclid(1_000_000), now)));
    }
    if !p.args_text.is_empty() {
        facts.push(("Arguments", arguments(&p.args_text)));
    }
    if let Some(wd) = &p.working_directory_text {
        facts.push(("Folder", named(wd)));
    }
    for (label, l) in [
        ("Parent", &p.parent),
        ("Session led by", &p.session_leader),
        ("Group led by", &p.process_group_leader),
    ] {
        if let Some(l) = l {
            let signed = l
                .signed_by_text
                .as_deref()
                .map_or("signer not known".to_string(), |s| {
                    format!("signed by {}", named(s))
                });
            let said = format!("{}, pid {}, {signed}", named(&l.executable_text), l.pid);
            facts.push((label, said));
        }
    }
}

/// A finding's evidence as `immunity finding <id>` gives it, from the same message: what it rests
/// on by its kind as facts, and as voices the rule's authors, the response layer's verdicts with
/// their reasons quoted, and the person's answer with who gave it and why. Every value from the
/// Mac is escaped and set apart. True when it sets out every part of what the finding's source
/// said (`Finding.value_text`): a vulnerable package's value is its package, its releases and each
/// record with its source, summary and fixes (`vulnerabilities::finding_detail`), all here while
/// the evidence names its records.
fn evidence(
    f: &v1::Finding,
    facts: &mut Vec<(&str, String)>,
    voices: &mut Vec<Voice>,
    now: i64,
) -> bool {
    use v1::evidence::Body;
    let mut set_out = false;
    let word = |s: &str| format!("<span class=\"w\">{}</span>", esc(s));
    match f.evidence.as_ref().and_then(|e| e.body.as_ref()) {
        Some(Body::PlaceChanged(p)) => {
            facts.push((
                "What happened",
                word(crate::finding_text::change_said(p.change)),
            ));
            if let Some(at) = p.read_as_before_at {
                let (before, after) = crate::finding_text::READ_AS_BEFORE;
                let said = format!("{} {} {}", word(before), view::when(at, now), word(after));
                facts.push(("Read back", said));
            }
            if p.presence_only == Some(true) {
                facts.push((
                    "Watched",
                    word(&format!(
                        "only for presence: {}",
                        crate::watched::PRESENCE_ONLY
                    )),
                ));
            }
            if p.change == v1::Change::NotRead as i32 {
                let latest = f.rests_on.last().map(|b| b.run_id.as_str());
                let why = f
                    .rests_on
                    .iter()
                    .rev()
                    .take_while(|b| Some(b.run_id.as_str()) == latest)
                    .find(|b| b.entry == "not_read")
                    .and_then(|b| b.new_value_text.as_deref());
                facts.push((
                    "Why",
                    why.map_or(word("the store gives no reason"), said_data),
                ));
            }
            let runs = p.runs.iter().map(|t| ("Runs", t));
            for (label, t) in runs.chain(p.started_by.iter().map(|t| ("Run by", t))) {
                let said = word(crate::finding_text::tie_said(t.state));
                let when = view::when(t.recorded_at, now);
                facts.push((label, format!("{} {said} {when}", named(&t.path_text))));
                if let Some(signer) = &t.signed_by_text {
                    facts.push(("Signer", said_data(signer)));
                }
            }
            if let Some(b) = crate::finding_text::signer_entry(f) {
                let (until, from) = crate::finding_text::SIGNER_SAID;
                let when = view::when(b.recorded_at, now);
                for (label, said, value) in [
                    ("Signer before", until, &b.old_value_text),
                    ("Signer after", from, &b.new_value_text),
                ] {
                    if let Some(value) = value {
                        let value = said_data(value);
                        facts.push((label, format!("{value} {} {when}", word(said))));
                    }
                }
            }
            for b in f.rests_on.iter().filter(|b| b.entry == "place_first_read") {
                if let Some(place) = &b.subject_text {
                    facts.push(("First read", named(place)));
                }
            }
        }
        Some(Body::ChangedInPlace(p)) => {
            match (&p.became_text, &p.files) {
                (Some(value), _) => facts.push(("It became", named(value))),
                // The files that changed, as the text names them; where a folder changed whole,
                // its path is from the Mac and its number of files is Immunity Core's.
                (None, Some(files)) => {
                    let (counts, entries) = crate::finding_text::files_said(files);
                    facts.push(("Files", word(&counts)));
                    for (label, x) in entries {
                        let shown = match x.folder {
                            true => {
                                let n = i64::try_from(x.files).unwrap_or(i64::MAX);
                                let n = word(&format!("({})", counted(n, "file", "files")));
                                format!("{} {n}", named(&format!("{}/", x.path_text)))
                            }
                            false => named(&x.path_text),
                        };
                        facts.push((label, shown));
                    }
                }
                (None, None) => {
                    if let Some(b) = f.rests_on.iter().rev().find(|b| {
                        b.entry == "changed" && b.predicate.as_deref() == Some("has_digest")
                    }) {
                        facts.push((
                            "Digest before",
                            (b.old_value_text.as_deref()).map_or(word("not known"), named),
                        ));
                        facts.push((
                            "Digest after",
                            (b.new_value_text.as_deref()).map_or(word("not known"), named),
                        ));
                    }
                }
            }
        }
        Some(Body::IndicatorMatched(p)) => {
            if let Some(value) = &p.indicators_text {
                facts.push(("Matched", named(value)));
            }
            if let Some(port) = p.port {
                facts.push(("Port", number(port)));
            }
            if let Some(transport) = &p.transport {
                facts.push(("Transport", word(transport)));
            }
            if let Some(p) = &p.process {
                process_facts(p, facts, now);
            }
        }
        Some(Body::DetachedProcess(p)) => process_facts(p, facts, now),
        Some(Body::VulnerablePackage(p)) => {
            if let Some(why) = p.no_longer_found {
                let said = crate::finding_text::no_longer_found_said(why);
                let as_then = crate::finding_text::as_then(p);
                facts.push(("No longer found", word(&format!("{said}{as_then}"))));
                if let Some(at) = p.no_longer_found_at {
                    facts.push(("Since", view::when(at, now)));
                }
            }
            if let Some(name) = &p.package_text {
                facts.push(("Package", named(name)));
            }
            for r in &p.releases {
                facts.push(("Version", named(&r.version_text)));
                facts.push(("Declared at", named(&r.at_text)));
            }
            set_out = !p.records.is_empty();
            for r in &p.records {
                facts.push(("Record", named(&r.id_text)));
                if !r.fixed_text.is_empty() {
                    let fixed = super::names(&r.fixed_text);
                    facts.push(("Fixed in", format!("<span class=\"mono\">{fixed}</span>")));
                }
                voices.push(Voice {
                    name: esc(&r.source),
                    said: r.summary_text.as_deref().map_or(String::new(), said_data),
                    detail: String::new(),
                    quote: None,
                });
            }
        }
        Some(Body::PublishedRuleMatched(p)) => {
            let rule = p.rule.clone().unwrap_or_default();
            if let Some(n) = p.matches {
                facts.push(("Matched", word(&counted(n as i64, "time", "times"))));
            }
            for (i, e) in p.events.iter().enumerate() {
                // Beside the latest, the first is the event that raised the finding.
                if i == 0 && p.events.len() > crate::events::EVIDENCE {
                    facts.push(("Raised by", "the event below".to_string()));
                }
                facts.extend(event_facts(e, now));
            }
            voices.push(Voice {
                name: format!("Published rule · {}", esc(&rule.set)),
                said: Name::given(&rule.title_text).html(),
                detail: if rule.level == v1::Level::NotStated as i32 {
                    String::new()
                } else {
                    format!(
                        "its authors rate it {}",
                        esc(&crate::text::word::<v1::Level>(rule.level))
                    )
                },
                quote: None,
            });
        }
        Some(Body::VerdictGiven(v)) => {
            facts.push((
                "About the rule",
                format!("<span class=\"mono\">{}</span>", Name::of(&v.rule).html()),
            ));
            for e in &v.events {
                facts.extend(event_facts(e, now));
            }
        }
        None => {}
    }
    if let Some(v) = &f.verdicts {
        for listed in &v.listed {
            let verdict = listed.verdict.clone().unwrap_or_default();
            let mut said = capital(&crate::text::word::<v1::VerdictKind>(verdict.kind));
            if let Some(c) = verdict.confidence {
                let _ = write!(said, ", how sure: {}", crate::text::word::<v1::Level>(c));
            }
            if listed.event_gone {
                said.push_str(
                    ". Its event was no longer in the log, so Immunity Core could not check that the rule matched it",
                );
            }
            voices.push(Voice {
                name: "Response layer".to_string(),
                said: esc(&said),
                detail: view::when(listed.recorded_at, now),
                quote: Some(verdict.reason_text.clone()),
            });
        }
    }
    // The earlier occurrence by its id, answered or not; the person's answer, then its answer.
    let earlier = (f.earlier.as_ref()).and_then(|e| Some((e.answer.as_ref(), e.finding.as_ref()?)));
    if let Some((_, r)) = earlier {
        facts.push(("Earlier", esc(&r.id)));
    }
    let then = earlier.and_then(|(a, r)| Some((a?, r)));
    let answers = f.answer.as_ref().map(|a| (a, None));
    for (a, before) in answers.into_iter().chain(then.map(|(a, r)| (a, Some(r)))) {
        let said = match a.until_at {
            Some(u) => format!("Expected until {}", view::when(u, now)),
            None => "Seen".to_string(),
        };
        let name = match v1::Via::try_from(a.via) {
            Ok(v1::Via::Agent) => "Your agent",
            _ => "Your answer",
        };
        voices.push(Voice {
            name: match before {
                Some(r) => format!("{name} before, to {}", esc(&r.id)),
                None => name.to_string(),
            },
            said,
            detail: format!(
                "answered {} {}",
                view::when(a.given_at, now),
                esc(crate::finding_text::given_by(a.via))
            ),
            quote: a.reason_text.clone(),
        });
    }
    set_out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_prints_names_and_what_a_source_said_as_text_cut_and_its_command_escaped_beside_the_copy_button()
     {
        // A file on the Mac may have been written for a person or an agent to read. Its name,
        // the thing's id and what a source said reach the page through the printer alone: a tag
        // is shown as text, a character that reorders text is written out, a secret is cut,
        // and the command an agent reads stays one escaped command with the fixed button after
        // it.
        let secret = ["invented", "-pass", "-word"].concat();
        let listed = v1::ListedFinding {
            finding: Some(v1::FindingRef {
                id: "<b>\"x".to_string(),
                rule: Some("watched.shell-profile".to_string()),
                about_text: "<i>about".to_string(),
                state: v1::FindingState::Open as i32,
                ..Default::default()
            }),
            kind_title: "Shell startup file".to_string(),
            where_text: "~/<img src=x>\u{202e}".to_string(),
            first_seen_at: 1,
            last_seen_at: 1,
            ..Default::default()
        };
        let whole = v1::Finding {
            title: "Invented title".to_string(),
            value_text: Some(format!("<script>said</script> --password={secret}")),
            ..Default::default()
        };
        let answers = Answers {
            findings: v1::Findings {
                findings: vec![listed],
                ..Default::default()
            },
            finding: Box::new(move |_| Ok(Some(whole.clone()))),
            ..Answers::none()
        };
        let mut out = String::new();
        table(&mut out, &answers, 0).unwrap();
        for raw in ["<b>", "<i>", "<img", "<script", "\u{202e}", secret.as_str()] {
            assert!(!out.contains(raw), "{raw}: {out}");
        }
        assert!(
            out.contains(
                "<span class=\"fw\"><bdi class=\"src\">~/&lt;img src=x&gt;\\u{202e}</bdi></span>"
            ),
            "{out}"
        );
        assert!(
            out.contains("<span class=\"said\"><bdi class=\"src\">&lt;script&gt;said&lt;/script&gt; --password=\\cut{"),
            "{out}"
        );
        let line = &out[out.find("<div class=\"fxb\">").unwrap()..];
        assert!(
            line.contains(&format!(
                "For your agent <span class=\"cmd\"><span class=\"mono\">immunity finding &lt;b&gt;&quot;x --json</span>{COPY}</span></span>"
            )),
            "{line}"
        );
    }

    #[test]
    fn every_finding_is_in_one_row_whatever_its_state_or_rule_and_what_the_cut_leaves_out_is_counted_in_findings()
     {
        // No finding is folded out of sight: one in a state this build does not know is open,
        // and the response layer's finding about its own finding is a row of its own. What the
        // cut leaves out is told in findings as the tabs count them, a pair two.
        let listed = |id: &str, rule: &str, about: &str, state: i32| v1::ListedFinding {
            finding: Some(v1::FindingRef {
                id: id.to_string(),
                rule: Some(rule.to_string()),
                about_text: about.to_string(),
                state,
                ..Default::default()
            }),
            ..Default::default()
        };
        let open = v1::FindingState::Open as i32;
        let mut all: Vec<v1::ListedFinding> = (0..ITEMS_SHOWN)
            .map(|n| {
                listed(
                    &format!("f{n}"),
                    "watched.shell-profile",
                    &format!("a{n}"),
                    99,
                )
            })
            .collect();
        all.push(listed("core", "sigma:x", "thing", open));
        all.push(listed("own", crate::verdict::RULE, "thing", open));
        all.push(listed("self", crate::verdict::RULE, "self", open));
        // Two findings in one row past the cut, each counted.
        for (id, project) in [("one", "dev/one"), ("two", "dev/two")] {
            let mut f = package(id, project);
            f.finding.as_mut().unwrap().urgent = false;
            all.push(f);
        }
        let about = |rule: &str| v1::Finding {
            evidence: Some(v1::Evidence {
                body: Some(v1::evidence::Body::VerdictGiven(v1::VerdictGiven {
                    rule: rule.to_string(),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        };
        let answers = Answers {
            findings: v1::Findings {
                findings: all,
                ..Default::default()
            },
            finding: Box::new(move |id| {
                Ok(match id {
                    "own" => Some(about("sigma:x")),
                    "self" => Some(about(crate::verdict::RULE)),
                    _ => None,
                })
            }),
            ..Answers::none()
        };
        let mut out = String::new();
        table(&mut out, &answers, 0).unwrap();
        let tab = format!("Open <span class=\"tn\">{}</span>", ITEMS_SHOWN + 5);
        assert!(out.contains(&tab), "{out}");
        assert!(out.contains(">5 more, the mildest;"), "{out}");
    }

    #[test]
    fn a_package_no_longer_found_says_why_first_and_its_kept_names_stay_escaped() {
        let f = v1::Finding {
            evidence: Some(v1::Evidence {
                body: Some(v1::evidence::Body::VulnerablePackage(
                    v1::VulnerablePackage {
                        package_text: Some("<b>left-pad".to_string()),
                        no_longer_found: Some(v1::NoLongerFound::ProjectGone as i32),
                        no_longer_found_at: Some(1_800_000_000 - 3600),
                        ..Default::default()
                    },
                )),
            }),
            ..Default::default()
        };
        let (mut facts, mut voices) = (Vec::new(), Vec::new());
        evidence(&f, &mut facts, &mut voices, 1_800_000_000);
        let names: Vec<&str> = facts.iter().map(|(k, _)| *k).collect();
        assert_eq!(names, ["No longer found", "Since", "Package"]);
        assert!(
            facts[0]
                .1
                .contains("the project is no longer on this Mac; what follows")
        );
        assert!(facts[2].1.contains("&lt;b&gt;left-pad") && !facts[2].1.contains("<b>"));
    }

    #[test]
    fn a_finding_with_two_signer_entries_says_the_latest_entry_s_two_values_with_its_time_and_nothing_of_the_first()
     {
        let (now, first, latest) = (1_800_000_000, 1_800_000_000 - 7200, 1_800_000_000 - 3600);
        let signed = |at: i64, old: &str, new: &str| v1::JournalEntry {
            recorded_at: at,
            entry: "changed".to_string(),
            predicate: Some("signed_by".to_string()),
            old_value_text: Some(old.to_string()),
            new_value_text: Some(new.to_string()),
            ..Default::default()
        };
        let f = v1::Finding {
            answered_at: now,
            evidence: Some(v1::Evidence {
                body: Some(v1::evidence::Body::PlaceChanged(v1::PlaceChanged {
                    change: v1::Change::Changed as i32,
                    ..Default::default()
                })),
            }),
            rests_on: vec![
                signed(first, "apple", "first signer"),
                // The mark the core made where it cut a secret stays its own.
                signed(
                    latest,
                    "second before",
                    "second after \\cut{gitleaks:github-pat 40}",
                ),
            ],
            ..Default::default()
        };
        let text = crate::finding_text::finding(&f, &crate::screen::Screen::pipe());
        for line in [
            format!(
                "    Signer       until the reading of {}: \"second before\"\n",
                view::utc(latest)
            ),
            format!(
                "                 from the reading of {}: \"second after \\cut{{gitleaks:github-pat 40}}\"\n",
                view::utc(latest)
            ),
        ] {
            assert!(text.contains(&line), "{line}\n{text}");
        }
        let (mut facts, mut voices) = (Vec::new(), Vec::new());
        evidence(&f, &mut facts, &mut voices, now);
        let signers: Vec<(&str, String)> = (facts.iter())
            .filter(|(k, _)| k.starts_with("Signer"))
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let at = view::when(latest, now);
        assert_eq!(
            signers,
            [
                (
                    "Signer before",
                    format!(
                        "<span class=\"mono\"><bdi class=\"src\">second before</bdi></span> <span class=\"w\">until the reading of</span> {at}"
                    )
                ),
                (
                    "Signer after",
                    format!(
                        "<span class=\"mono\"><bdi class=\"src\">second after \\cut{{gitleaks:github-pat 40}}</bdi></span> <span class=\"w\">from the reading of</span> {at}"
                    )
                ),
            ]
        );
        for page_or_text in [text, format!("{signers:?}")] {
            assert!(!page_or_text.contains("first signer") && !page_or_text.contains("apple"));
            assert!(!page_or_text.contains(&view::utc(first)));
        }
    }

    #[test]
    fn a_published_rule_s_event_that_raised_its_finding_is_named_so_only_beside_the_latest() {
        // The message holds the event that raised the finding first only when it holds more
        // than the latest: then, and only then, the page says which it is.
        let raised = |n: usize| {
            let start = v1::Event {
                body: Some(v1::event::Body::ProgramStart(v1::ProgramStart::default())),
            };
            let f = v1::Finding {
                evidence: Some(v1::Evidence {
                    body: Some(v1::evidence::Body::PublishedRuleMatched(
                        v1::PublishedRuleMatched {
                            events: vec![start; n],
                            ..Default::default()
                        },
                    )),
                }),
                ..Default::default()
            };
            let (mut facts, mut voices) = (Vec::new(), Vec::new());
            evidence(&f, &mut facts, &mut voices, 0);
            facts.iter().position(|(k, _)| *k == "Raised by")
        };
        assert_eq!(raised(crate::events::EVIDENCE), None);
        assert_eq!(raised(crate::events::EVIDENCE + 1), Some(0));
    }

    /// An open finding of a malicious package in a project, as the list gives it.
    fn package(id: &str, project: &str) -> v1::ListedFinding {
        v1::ListedFinding {
            finding: Some(v1::FindingRef {
                id: id.to_string(),
                rule: Some("osv.malicious".to_string()),
                about_text: format!("component:machine:mac/{project}/npm/left-pad"),
                state: v1::FindingState::Open as i32,
                severity: Some(v1::Level::Critical as i32),
                confidence: Some(v1::Level::High as i32),
                urgent: true,
            }),
            short_title: "Malicious package in a project".to_string(),
            package_text: Some("left-pad".to_string()),
            releases_text: vec!["1.0.0".to_string()],
            where_text: format!("~/{project}/package-lock.json"),
            first_seen_at: 1,
            last_seen_at: 1,
            ..Default::default()
        }
    }

    /// The table of these findings, each read whole as `wholes` gives it by id.
    fn drawn_with(all: Vec<v1::ListedFinding>, wholes: Vec<(String, v1::Finding)>) -> String {
        let answers = Answers {
            findings: v1::Findings {
                findings: all,
                ..Default::default()
            },
            finding: Box::new(move |id| {
                Ok((wholes.iter())
                    .find(|(of, _)| of == id)
                    .map(|(_, f)| f.clone()))
            }),
            ..Answers::none()
        };
        let mut out = String::new();
        table(&mut out, &answers, 0).unwrap();
        out
    }

    /// The ids in each row the page draws: the row's own, then every one inside it.
    fn rows(page: &str) -> Vec<Vec<String>> {
        (page.split("<details class=\"fr").skip(1))
            .map(|r| {
                let r = &r[..r.find("</details>").unwrap()];
                (r.split(" id=\"").skip(1))
                    .map(|s| {
                        let id = &s[..s.find('"').unwrap()];
                        id.strip_prefix("answered-").unwrap_or(id).to_string()
                    })
                    .collect()
            })
            .collect()
    }

    /// What a source said is said once in an opened row. A vulnerable package's value is its
    /// package, releases and records, each with its source's own words: while the evidence names
    /// its records, the value is not drawn again beside them; with none named it is, as for any
    /// other finding.
    #[test]
    fn what_a_source_said_is_drawn_once_and_beside_the_evidence_only_where_the_evidence_lacks_it() {
        let summary = "left-pad lets an invented input run code";
        let whole = |records: &[v1::PackageRecord]| v1::Finding {
            value_text: Some(format!(
                "left-pad 1.0.0; GHSA-x from GitHub Advisory Database: {summary}"
            )),
            evidence: Some(v1::Evidence {
                body: Some(v1::evidence::Body::VulnerablePackage(
                    v1::VulnerablePackage {
                        package_text: Some("left-pad".to_string()),
                        records: records.to_vec(),
                        ..Default::default()
                    },
                )),
            }),
            ..Default::default()
        };
        let record = v1::PackageRecord {
            id_text: "GHSA-x".to_string(),
            source: "GitHub Advisory Database".to_string(),
            summary_text: Some(summary.to_string()),
            ..Default::default()
        };
        for (records, beside) in [(vec![record], false), (vec![], true)] {
            let all = vec![package("f1", "dev/cart"), package("f2", "dev/shop")];
            let wholes = vec![
                ("f1".to_string(), whole(&records)),
                ("f2".to_string(), whole(&records)),
            ];
            let page = drawn_with(all, wholes);
            assert_eq!(page.contains("<dt>Source said</dt>"), beside, "{page}");
            assert_eq!(page.matches(summary).count(), 1, "{page}");
        }
    }

    #[test]
    fn a_row_of_several_draws_every_finding_by_its_own_id_with_no_cap_and_the_tabs_count_findings()
    {
        // Three hundred projects with the same package and release: one row, which says in how
        // many projects it is, and holds each finding on its own line with the command that
        // answers it. The tab counts findings, never rows.
        let n = 300;
        let mut all: Vec<v1::ListedFinding> = (0..n)
            .map(|k| package(&format!("f{k}"), &format!("dev/p{k}")))
            .collect();
        all.push(package("other", "dev/p0"));
        all[n].releases_text = vec!["2.0.0".to_string()];
        let page = drawn_with(all, Vec::new());
        assert!(
            page.contains(&format!("Open <span class=\"tn\">{}</span>", n + 1)),
            "{page}"
        );
        let rows = rows(&page);
        assert_eq!(rows.len(), 2, "{rows:?}");
        let ids: Vec<String> = (0..n).map(|k| format!("f{k}")).collect();
        let mut drawn = rows[0].clone();
        drawn.sort();
        let mut all = ids.clone();
        all.sort();
        assert_eq!(drawn, all);
        assert!(
            page.contains("<span class=\"fc\">300 projects</span>"),
            "{page}"
        );
        for id in ids.iter().chain(["other".to_string()].iter()) {
            let command = format!("immunity finding {id} --json</span>");
            assert_eq!(page.matches(&command).count(), 1, "{id}");
        }
    }

    #[test]
    fn the_lines_of_a_row_of_several_are_in_the_order_of_where_each_finding_is() {
        // A person looks for a project by its name: the lines follow the text of where each
        // finding is, whatever order the ids and the answer give them, and each keeps its id.
        let all = vec![
            package("f1", "dev/cart"),
            package("f2", "dev/shop"),
            package("f3", "dev/api"),
        ];
        let page = drawn_with(all, Vec::new());
        let places: Vec<&str> = (page.split("<span class=\"p\"><bdi class=\"src\">~/dev/"))
            .skip(1)
            .map(|l| &l[..l.find('/').unwrap()])
            .collect();
        assert_eq!(places, ["api", "cart", "shop"], "{page}");
        assert_eq!(rows(&page), [["f1", "f3", "f2"]], "{page}");
    }

    #[test]
    fn findings_of_another_rule_thing_release_level_state_or_answer_are_never_drawn_in_one_row() {
        // Beside two findings that share every part of the key, each of the others differs from
        // them in one part alone, and so is a row of its own; one with the response layer's word
        // is never joined either.
        let base = || package("a", "dev/one");
        let mut twin = package("b", "dev/two");
        (twin.first_seen_at, twin.last_seen_at) = (5, 9);
        let mut variants: Vec<v1::ListedFinding> = Vec::new();
        let mut vary = |id: &str, change: &dyn Fn(&mut v1::ListedFinding)| {
            let mut f = base();
            let r = f.finding.as_mut().unwrap();
            r.id = id.to_string();
            r.about_text = format!("component:machine:mac/dev/{id}/npm/left-pad");
            change(&mut f);
            variants.push(f);
        };
        fn r(f: &mut v1::ListedFinding) -> &mut v1::FindingRef {
            f.finding.as_mut().unwrap()
        }
        vary("rule", &|f| r(f).rule = Some("osv.exploited".to_string()));
        vary("name", &|f| {
            r(f).about_text = "component:machine:mac/dev/name/npm/left-pads".to_string()
        });
        vary("ecosystem", &|f| {
            r(f).about_text = "component:machine:mac/dev/ecosystem/PyPI/left-pad".to_string()
        });
        vary("release", &|f| f.releases_text = vec!["1.0.1".to_string()]);
        vary("severity", &|f| {
            r(f).severity = Some(v1::Level::High as i32)
        });
        vary("confidence", &|f| {
            r(f).confidence = Some(v1::Level::Medium as i32)
        });
        vary("urgent", &|f| r(f).urgent = false);
        vary("verdict", &|f| {
            f.verdicts = Some(v1::Verdicts {
                total: 1,
                ..Default::default()
            })
        });
        // Two answered alike but for one part of the answer: which, how it came, until when.
        let answered = |f: &mut v1::ListedFinding, given, via, until_at| {
            r(f).state = v1::FindingState::Expected as i32;
            f.answer = Some(v1::Answer {
                given,
                via,
                until_at,
                in_force: true,
                ..Default::default()
            });
        };
        let (expected, agent) = (v1::AnswerKind::Expected as i32, v1::Via::Agent as i32);
        vary("answered", &|f| answered(f, expected, agent, Some(5)));
        vary("given", &|f| {
            answered(f, v1::AnswerKind::Seen as i32, agent, Some(5))
        });
        vary("via", &|f| {
            answered(f, expected, v1::Via::App as i32, Some(5))
        });
        vary("until", &|f| answered(f, expected, agent, Some(6)));
        vary("state", &|f| {
            answered(f, expected, agent, Some(5));
            r(f).state = v1::FindingState::Seen as i32;
        });
        let alone: Vec<String> = variants
            .iter()
            .map(|f| f.finding.as_ref().unwrap().id.clone())
            .collect();
        let page = drawn_with([vec![base(), twin], variants].concat(), Vec::new());
        let rows = rows(&page);
        assert!(
            rows.contains(&vec!["a".to_string(), "b".to_string()]),
            "{rows:?}"
        );
        for id in alone {
            assert!(rows.contains(&vec![id.clone()]), "{id}: {rows:?}");
        }
        // The row says the latest time any finding in it was seen, and opened, the first too.
        let at = |s: i64| format!("<time datetime=\"1970-01-01T00:00:0{s}Z\"");
        assert!(
            page.contains(&format!("<span class=\"fs\">{}", at(9))),
            "{page}"
        );
        assert!(page.contains(&format!("First seen {}", at(1))), "{page}");
        assert!(page.contains(&format!(" · last seen {}", at(9))), "{page}");
    }

    #[test]
    fn an_answer_through_an_agent_in_a_row_of_several_stands_on_its_finding_s_line_with_its_reason()
    {
        // Two findings answered alike through an agent, each with its own reason: the row says
        // the answer once, and each line says who gave it and why, so neither is quieted out of
        // sight. What both say alike (the package, the record) is said once for the row, and what
        // one source said of one finding only on its line.
        let answer = |reason: &str| v1::Answer {
            given: v1::AnswerKind::Expected as i32,
            via: v1::Via::Agent as i32,
            until_at: Some(86_400),
            reason_text: Some(reason.to_string()),
            in_force: true,
            ..Default::default()
        };
        let listed = |id: &str, project: &str, reason: &str| {
            let mut f = package(id, project);
            f.finding.as_mut().unwrap().state = v1::FindingState::Expected as i32;
            f.answer = Some(answer(reason));
            f
        };
        let whole = |reason: &str| v1::Finding {
            title: "Invented title".to_string(),
            value_text: Some(format!("said {reason}")),
            answer: Some(answer(reason)),
            evidence: Some(v1::Evidence {
                body: Some(v1::evidence::Body::VulnerablePackage(
                    v1::VulnerablePackage {
                        package_text: Some("left-pad".to_string()),
                        ..Default::default()
                    },
                )),
            }),
            ..Default::default()
        };
        let page = drawn_with(
            vec![
                listed("a", "dev/one", "invented: first"),
                listed("b", "dev/two", "invented: second"),
            ],
            vec![
                ("a".to_string(), whole("invented: first")),
                ("b".to_string(), whole("invented: second")),
            ],
        );
        assert_eq!(rows(&page), [["a", "b"]], "{page}");
        assert_eq!(
            page.matches("<span class=\"ans\">Answered: expected until ")
                .count(),
            1
        );
        let lines: Vec<&str> = page.split("<li").skip(1).collect();
        assert_eq!(lines.len(), 2, "{page}");
        for (line, reason) in lines.iter().zip(["invented: first", "invented: second"]) {
            assert!(
                line.contains("<div class=\"vn\">Your agent</div>") && line.contains(reason),
                "{line}"
            );
            assert!(
                !line.contains("<dt>Package</dt>") && !line.contains("Immunity Core"),
                "{line}"
            );
            assert!(line.contains(&format!("said {reason}")), "{line}");
        }
        let shared = &page[..page.find("<div class=\"in\">").unwrap()];
        assert_eq!(shared.matches("<dt>Package</dt>").count(), 1, "{page}");
        assert!(
            !shared.contains("Your agent") && !shared.contains("said invented"),
            "{shared}"
        );
    }
}
