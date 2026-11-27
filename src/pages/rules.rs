//! The page of published rules, drawn from what `immunity rules` answers and what the status
//! says the rules do now (`RulesNow`): every rule checked in full or in part, by place, then by
//! level, the most severe first. Whether a rule watches is the status's word, never decided
//! here: a rule watches only while the event level runs and the status does not name it among
//! those that do not (`not_watching`); a rule checked in part is never counted as watching. Every
//! text of a rule is its own, printed through `secrets::Name` and `secrets::Said`.

use super::{RULES_TITLE, capital, top};
use crate::contract::v1;
use crate::secrets::Name;
use crate::view::{FOOT, esc, utc};

/// The two places of a rule this version checks, as the rules page names them: its anchor
/// there, its heading, and what being there means. A rule that cannot be checked is not on the
/// page: `immunity rules` counts those, and `docs/coverage.md` says what would open them.
const PLACED: [(&str, &str, &str); 2] = [
    (
        "evaluated",
        "Checked in full",
        "Everything these rules look for is in what the event level gives: for a program start, the program, its command line and the program that started it; for a file created or renamed, its path and the program that did it.",
    ),
    (
        "in-part",
        "Checked in part",
        "Each of these rules looks for one of several alternatives. Those an event can show are checked, and a rule's details name the rest.",
    ),
];

/// A rule's level for a person and for the stylesheet: its name, or that its set states none, or
/// not known for a rule that could not be read. `None` as the place on the scale for a rule of a
/// set that states no level, which is a group of its own.
fn level(rule: Option<&v1::Rule>) -> (&'static str, &'static str) {
    use v1::Level as L;
    match rule.map(|r| L::try_from(r.level)) {
        None => ("unknown", "unknown"),
        Some(Ok(L::NotStated)) => ("none", crate::sigma::NO_LEVEL),
        Some(Ok(L::Informational)) => ("informational", "informational"),
        Some(Ok(L::Low)) => ("low", "low"),
        Some(Ok(L::Medium)) => ("medium", "medium"),
        Some(Ok(L::High)) => ("high", "high"),
        Some(Ok(L::Critical)) => ("critical", "critical"),
        // A level the reader does not know is read as the highest (`common.proto`).
        Some(_) => ("critical", "critical"),
    }
}

/// Why a rule checked in full does not watch on this Mac, as the status names it.
fn not_watching(reason: i32) -> &'static str {
    use v1::NotWatchingReason as R;
    match R::try_from(reason) {
        Ok(R::FileEventsNotCollected) => {
            "Not watching on this Mac: the collector installed here records program starts only. Installing the event level again adds files created and renamed."
        }
        Ok(R::CollectorDoesNotKeep) => {
            "Not watching on this Mac: it reads what the collector installed here does not keep. Installing the event level again adds it."
        }
        Ok(R::KeptNeverFilled) => {
            "Not watching on this Mac: it reads what the collector keeps and no line has given a value for yet."
        }
        Ok(R::NoLongerArriving) => {
            "Not watching on this Mac: it reads what the collector keeps, and the latest lines give no value for it."
        }
        Ok(R::NotYetKnown) => {
            "Not watching on this Mac: it reads what no line read so far would carry, so whether the collector keeps it is not yet known."
        }
        _ => "Not watching on this Mac.",
    }
}

/// Every published rule this build checks, in full or in part, for a person: by place, then
/// by level, the most severe first, as `immunity rules` orders them. Each with its title, its
/// level, what it looks for in its authors' words, its ATT&CK techniques and its authors, how
/// many times it matched in the last day, and, where it does not watch or is not checked in full,
/// why. The counts at the top are the status's.
pub fn page(m: &v1::Rules, status: &v1::Status, now: i64) -> String {
    let r = status.rules.clone().unwrap_or_default();
    let from: Vec<String> = m
        .sources
        .iter()
        .map(|s| match &s.commit_date {
            Some(date) => format!("{}, as published on {date}", s.set),
            None => format!(
                "{}, at commit {}",
                s.set,
                s.commit.get(..12).unwrap_or(&s.commit)
            ),
        })
        .collect();
    let mut out = top(
        RULES_TITLE,
        &format!("From {} · this page made {}", from.join("; "), utc(now)),
    );
    let mut w = |s: String| out.push_str(&s);
    let shipped = crate::sigma::Rules::shipped();
    w(format!(
        "<p>{}</p>\n<div class=\"scale\">\n",
        esc(&crate::text::rules_said(&shipped.sources_said(), &r))
    ));
    for ((anchor, title, _), n) in PLACED.iter().zip([r.evaluated, r.in_part]) {
        w(format!(
            "<p><span class=\"num\">{n}</span> <a href=\"#{anchor}\">{}</a></p>\n",
            esc(title)
        ));
    }
    w("</div>\n".to_string());
    // The rules that do not watch while the level runs, by name, with why: the status's.
    let unwatched = |name: &str| {
        r.not_watching
            .iter()
            .find(|n| (n.rule.as_ref()).is_some_and(|x| x.name == name))
    };
    let on = r.watching == Some(true);
    let names = |list: &[String]| {
        let named: Vec<String> = list
            .iter()
            .map(|s| format!("<span class=\"mono\">{}</span>", Name::given(s).html()))
            .collect();
        named.join(", ")
    };
    for (((anchor, title, means), group), full) in PLACED
        .iter()
        .zip([&m.evaluated, &m.in_part])
        .zip([true, false])
    {
        w(format!(
            "<section id=\"{anchor}\">\n<h2>{}</h2>\n<p class=\"muted\">{}</p>\n",
            esc(title),
            esc(means)
        ));
        if group.is_empty() {
            w("<p class=\"muted\">None.</p>\n".to_string());
        }
        let mut heading: Option<&str> = None;
        for s in group {
            let rule = s.rule.as_ref();
            let (this, said) = level(rule);
            // A heading for each level, from the most severe down; the rules of a set that states
            // no level come last under their own, as a group and not as a level.
            if heading != Some(this) {
                let words = if this == "none" {
                    crate::sigma::NO_LEVEL_GROUP
                } else {
                    said
                };
                w(format!("<h3>{}</h3>\n", esc(&capital(words))));
                heading = Some(this);
            }
            // Its title, else the file of a rule that could not be read, then its set in words.
            // One element holds both: the heading is a flex row, and its gap is for the chip.
            let title = rule.map_or(&s.file, |r| &r.title_text);
            w(format!(
                "<article class=\"rule\">\n<h4><span>{} ({})</span> <span class=\"chip lvl-{this}\">{said}</span></h4>\n",
                Name::given(title).html(),
                esc(&s.set)
            ));
            // How many times it matched in the last day; and, only of a rule that watches now,
            // that it did not match.
            let missing = rule.and_then(|x| unwatched(&x.name));
            let matched = s.matches_last_day.unwrap_or(0);
            if matched > 0 {
                w(format!(
                    "<p class=\"meta\">Matched {} in the last day.</p>\n",
                    crate::sigma::times(matched as i64)
                ));
            } else if on && full && rule.is_some() && missing.is_none() {
                w("<p class=\"meta\">No match in the last day.</p>\n".to_string());
            }
            if let Some(n) = missing.filter(|_| on && full) {
                w(format!(
                    "<p class=\"missing\">{}</p>\n",
                    not_watching(n.reason)
                ));
            }
            // What a rule checked in part goes without is a detail of the rule, said with its
            // other details.
            let given_by = match s.events.as_deref() == Some(m.file_events.as_str()) {
                true => "a file event",
                false => "a program start",
            };
            let without: Vec<String> = s
                .never_matches
                .iter()
                .map(|b| match (&b.selection_text, &b.left_out_text) {
                    (Some(selection), _) => format!(
                        "<li>Checked without the alternative {}, which needs {}; {given_by} does not give it.</li>\n",
                        names(std::slice::from_ref(selection)),
                        names(&b.fields_text),
                    ),
                    (None, _) if !b.fields_text.is_empty() => format!(
                        "<li>Checked without an alternative of the upstream rule, which needs {}; {given_by} does not give it.</li>\n",
                        names(&b.fields_text),
                    ),
                    (None, said) => format!(
                        "<li>Checked without an alternative of the upstream rule, left out in translation, {}.</li>\n",
                        Name::given(said.as_deref().unwrap_or("")).html()
                    ),
                })
                .collect();
            let Some(rule) = rule else {
                w("</article>\n".to_string());
                continue;
            };
            w(format!(
                "<details>\n<summary>{}</summary>\n<ul class=\"about\">\n",
                s.description_text
                    .as_deref()
                    .map_or("Details".to_string(), |d| format!(
                        "<span class=\"desc\">{}</span>",
                        Name::given(d).html()
                    ))
            ));
            if !rule.techniques_text.is_empty() {
                w(format!(
                    "<li>ATT&amp;CK: {}</li>\n",
                    names(&rule.techniques_text)
                ));
            }
            if let Some(a) = &rule.author_text {
                w(format!("<li>Author: {}</li>\n", Name::given(a).html()));
            }
            w(without.concat());
            w(format!(
                "<li>Published as {}, in <span class=\"mono\">{}</span></li>\n</ul>\n</details>\n</article>\n",
                esc(s.status.as_deref().unwrap_or("")),
                esc(&s.file)
            ));
        }
        w("</section>\n".to_string());
    }
    w(licences());
    out.push_str(FOOT);
    out
}

/// The licences' addresses, as the sets' NOTICEs give them. Addresses are named, not linked: no
/// page of the view carries a web address to follow.
fn licences() -> String {
    use crate::sigma;
    let named = |notice: &'static str, marker: &str| {
        notice
            .split_whitespace()
            .find(|word| word.contains(marker))
            .map_or("", |word| word.trim_end_matches([',', '.']))
    };
    let licence = named(
        include_str!("../../rules/sigma/NOTICE"),
        "Detection-Rule-License",
    );
    let elastic_licence = named(
        include_str!("../../rules/elastic/NOTICE"),
        "licensing/elastic-license",
    );
    let behaviour_licence = named(
        include_str!("../../rules/elastic-behaviour/NOTICE"),
        "licensing/elastic-license",
    );
    let bare = |url: &'static str| url.strip_prefix("https://").unwrap_or(url);
    format!(
        "<footer class=\"licence\">\n<p class=\"meta\">SigmaHQ's rules are copied unchanged from its rule set, <span class=\"mono\">{}</span>, at commit <span class=\"mono\">{}</span> of {}. They are licensed under the Detection Rule License 1.1, <span class=\"mono\">{}</span>, and each keeps its authors, shown with it.</p>\n<p class=\"meta\">Elastic's rules are translated mechanically into Sigma from its detection rules, <span class=\"mono\">{}</span>, at commit <span class=\"mono\">{}</span>; none is edited by hand. They carry Elastic License 2.0, <span class=\"mono\">{}</span>, and each keeps its authors, shown with it.</p>\n<p class=\"meta\">Elastic's behaviour rules are translated the same way from <span class=\"mono\">{}</span> at commit <span class=\"mono\">{}</span>, under Elastic License 2.0, <span class=\"mono\">{}</span>. They state no level and name no authors.</p>\n</footer>\n",
        esc(bare(sigma::SOURCE)),
        sigma::COMMIT,
        sigma::COMMIT_DATE,
        esc(bare(licence)),
        esc(bare(sigma::ELASTIC.url)),
        sigma::ELASTIC.commit,
        esc(bare(elastic_licence)),
        esc(bare(sigma::ELASTIC_BEHAVIOUR.url)),
        sigma::ELASTIC_BEHAVIOUR.commit,
        esc(bare(behaviour_licence)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn the_rules_page_says_no_match_only_of_a_rule_the_status_counts_as_watching_and_names_why_one_does_not()
     {
        // "No match in the last day" is calm: it is said only of a rule the status counts as
        // watching. A rule checked in full that reads what no line has given a value for has
        // judged nothing, and says so instead, with which, as the status names it: the collector
        // does not keep it, keeps it and never filled it, or no line was read yet. A rule checked
        // in part is never counted as watching, so it says neither.
        use crate::events::{Arrival, Arrivals, Files, Level, RUNNING, Series, Tally};
        use crate::sigma::{ELASTIC, Rules};
        let rule = |id: &str, title: &str, detection: &str, left_out: &str| -> &'static str {
            Box::leak(
                format!(
                    "title: {title}\nid: {id}\nstatus: test\nlevel: high\n\
                     logsource: {{\"product\": \"macos\", \"category\": \"file_event\"}}\n\
                     detection:\n{detection}{}",
                    crate::sigma::testing::record_of(&ELASTIC, "\"high\"", left_out)
                )
                .into_boxed_str(),
            )
        };
        let signer = "  s1: {\"process.code_signature.signing_id|cased\": [\"com.example\"]}\n  condition: s1\n";
        let rules = Rules::load_as(
            &ELASTIC,
            &[
                (
                    "full.yml",
                    rule(
                        "00000000-0000-4000-8000-000000000001",
                        "Invented in full",
                        signer,
                        "",
                    ),
                ),
                (
                    "part.yml",
                    rule(
                        "00000000-0000-4000-8000-000000000002",
                        "Invented in part",
                        signer,
                        "\"needs_fields process.code_signature.trusted\"",
                    ),
                ),
            ],
        );
        let on = Arrival::Kept(Some(1));
        let sig = |a| Arrivals::from([on, on, a, on, a]);
        let script = |a| Arrivals::from([on, a, on, on, on]);
        let level_as = |state: &str, collected: bool, arrivals| Level {
            state: state.to_string(),
            read_at: 0,
            stored: (state.to_string(), 0),
            written: None,
            said_by: None,
            said: None,
            reason: None,
            version: None,
            since_check: Tally::default(),
            last_day: Tally::default(),
            matches_last_day: BTreeMap::new(),
            matches_last_week: BTreeMap::new(),
            starts_by_hour: Series::default(),
            starts_by_minute: Series::default(),
            files: Files {
                collected,
                ..Files::default()
            },
            arrivals,
            cap: None,
        };
        let level = |arrivals| level_as(RUNNING, true, arrivals);
        let drawn = |rules: &Rules, l: &Level| {
            let none = BTreeMap::new();
            let m = rules.message(Some((&none, &none)));
            let r = crate::status::rules_now_of(rules, Some(l));
            page(
                &m,
                &v1::Status {
                    rules: Some(r),
                    ..Default::default()
                },
                0,
            )
        };
        let page = |l: &Level| drawn(&rules, l);
        let said = "Not watching on this Mac: it reads what the collector installed here does not keep. Installing the event level again adds it.";
        let earlier = page(&level(sig(Arrival::NotKept)));
        assert_eq!(earlier.matches(said).count(), 1, "{earlier}");
        assert!(!earlier.contains("No match in the last day"), "{earlier}");
        let empty = page(&level(sig(Arrival::Kept(None))));
        assert_eq!(
            empty
                .matches("Not watching on this Mac: it reads what the collector keeps and no line has given a value for yet.")
                .count(),
            1,
            "{empty}"
        );
        assert!(!empty.contains("No match in the last day"), "{empty}");
        let stopped = page(&level(sig(Arrival::NoLonger(1))));
        assert_eq!(
            stopped
                .matches("Not watching on this Mac: it reads what the collector keeps, and the latest lines give no value for it.")
                .count(),
            1,
            "{stopped}"
        );
        assert!(!stopped.contains("No match in the last day"), "{stopped}");
        let unknown = page(&level(sig(Arrival::Unknown)));
        assert_eq!(
            unknown
                .matches("so whether the collector keeps it is not yet known")
                .count(),
            1,
            "{unknown}"
        );
        assert!(!unknown.contains("No match in the last day"), "{unknown}");
        // The count at the top counts neither among the rules watching file events.
        let r = crate::status::rules_now_of(&rules, Some(&level(sig(Arrival::NotKept))));
        let said_now = crate::text::rules_said("", &r);
        assert!(
            said_now.contains("0 every program start and 0 every file created or renamed"),
            "{said_now}"
        );
        let now = page(&level(sig(on)));
        assert!(!now.contains(said), "{now}");
        assert_eq!(now.matches("No match in the last day.").count(), 1, "{now}");
        // One reason at a time: while file events are not collected, that is the one said.
        let no_files = page(&level_as(RUNNING, false, sig(Arrival::NotKept)));
        assert!(!no_files.contains(said), "{no_files}");
        assert!(
            no_files.contains("records program starts only"),
            "{no_files}"
        );
        // With no collector running there is no earlier collector to name, though nothing
        // is known to arrive; and nothing watches, so no rule says it did not match.
        let off = page(&level_as("not_installed", false, Arrivals::default()));
        assert!(!off.contains("Not watching on this Mac: it reads"), "{off}");
        assert!(!off.contains("No match in the last day"), "{off}");
        // The same for a rule about program starts, which no change of file events covers.
        let starts = crate::sigma::testing::process_kept();
        let page = |l: &Level| drawn(&starts, l);
        let earlier = page(&level(script(Arrival::NotKept)));
        assert_eq!(earlier.matches(said).count(), 1, "{earlier}");
        let off = page(&level_as("not_installed", false, Arrivals::default()));
        assert!(!off.contains(said), "{off}");
    }
}
