//! What could not be read, on the summary: what the band counts (`NotRead`) and the section
//! "Could not be read" that tells each thing whole, once (`section`). Drawn from the status alone:
//! each cause it calls a fault (`Uncovered.fault`), and each other line of the default status about
//! a reading or a download that failed (`overview::Of::Reading`), as `overview::told` decides them
//! for the text. Every name and reason from the Mac is printed through `secrets::Name` and
//! `secrets::Said`.

use super::{NOT_READ, NOT_READ_TITLE, TERMINAL, apart, fault_html, grouped};
use crate::contract::v1;
use crate::covered::YOU;
use crate::overview::Of;
use crate::view::{Out, counted, esc};
use std::fmt::Write;

/// What could not be read, as the band counts it and its section tells it: each cause the status
/// calls a fault, those the person can fix first, and each other line of the default status about
/// a reading or a download that failed (`overview::Of::Reading`). With the states the band says,
/// every line the text lists, each once.
pub(super) struct NotRead<'a> {
    causes: Vec<&'a v1::Uncovered>,
    readings: Vec<crate::overview::Fault>,
}

impl<'a> NotRead<'a> {
    pub(super) fn of(r: &'a v1::Status) -> NotRead<'a> {
        let (mut causes, others): (Vec<&v1::Uncovered>, Vec<&v1::Uncovered>) =
            (r.not_covered.iter().filter(|u| u.fault)).partition(|u| u.who == YOU);
        causes.extend(others);
        let told = crate::overview::told(r, &TERMINAL);
        let readings = (told.faults.into_iter())
            .filter(|f| f.about() == Of::Reading)
            .collect();
        NotRead { causes, readings }
    }

    /// How many things could not be read: each cause the things it counts (`Uncovered.count`, the
    /// number its title says), one where it counts none, and each other reading one, since it
    /// carries no number.
    pub(super) fn len(&self) -> u64 {
        let causes: u64 = self.causes.iter().map(|u| things(u)).sum();
        causes + self.readings.len() as u64
    }

    /// How many things could not be read, in `words`, one and many, and after `and` how many of
    /// them the person can fix, counted the same way.
    fn counted(&self, (one, many): (&str, &str), and: &str) -> String {
        let yours: u64 = (self.causes.iter().filter(|u| u.who == YOU))
            .map(|u| things(u))
            .sum();
        let n = counted(self.len() as i64, one, many);
        match yours {
            0 => n,
            y => format!("{n}{and}{} you can fix", grouped(y as i64)),
        }
    }
}

/// The things a cause is about, as its title counts them, and one where it counts none.
fn things(u: &v1::Uncovered) -> u64 {
    u.count.max(1)
}

/// The words of the line that counts what could not be read, while something could not: `!` and
/// a link to `href`, where "Could not be read" tells each thing. The band and the page of this Mac
/// draw these words, each in its own line, so the two never count apart.
pub(super) fn line(r: &v1::Status, href: &str) -> Option<String> {
    let n = NotRead::of(r);
    (n.len() > 0).then(|| {
        format!(
            "! <a href=\"{href}\">{}</a>",
            esc(&n.counted(
                ("thing could not be read", "things could not be read"),
                ", "
            ))
        )
    })
}

/// Every thing that could not be read, each once, where the band's count leads (`NotRead`): a
/// cause by its own message (`uncovered`), and any other reading that failed as the text says
/// it, its words, what its source said and its command. Drawn only while something could not be
/// read, so it never says that everything was; else only its anchor stands, with no words, where
/// the link `store.view_sections` names for it lands.
pub(super) fn section(out: &mut String, r: &v1::Status) -> Out {
    let n = NotRead::of(r);
    if n.len() == 0 {
        writeln!(out, "<div id=\"{NOT_READ}\"></div>")?;
        return Ok(());
    }
    writeln!(
        out,
        "<section id=\"{NOT_READ}\">\n<div class=\"wsh\"><h2>{NOT_READ_TITLE}</h2><span class=\"n\">{}</span></div>",
        esc(&n.counted(("thing", "things"), " · "))
    )?;
    for u in &n.causes {
        uncovered(out, u)?;
    }
    // A reading carries no advice: only a cause does, told above by its own message.
    for f in &n.readings {
        let (words, said, tail, c, _) = f.parts();
        let said = said.map(|s| (s, f.said_is_ours()));
        writeln!(
            out,
            "<article class=\"item\">\n<p class=\"who\"></p>\n<div>\n<h3>{}</h3>\n</div>\n</article>",
            fault_html(words, said, tail, c)
        )?;
    }
    out.push_str("</section>\n");
    Ok(())
}

/// One cause that is a fault, in full: who can act on it, the person or no one, as a label beside
/// it; its title; the examples the status gives with what their sources said (`apart`); what it
/// means and what to do. One nothing the person does changes is tried again at every check.
fn uncovered(out: &mut String, u: &v1::Uncovered) -> Out {
    let (who, label) = match u.who == YOU {
        true => (" you", "<span class=\"dot off look\"></span>You can fix"),
        false => ("", "<span class=\"dot off\"></span>Tried at every check"),
    };
    writeln!(
        out,
        "<article class=\"item\" id=\"{}\">\n<p class=\"who{who}\">{label}</p>\n<div>\n<h3>{}</h3>",
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
        "<p>{}</p>\n<p class=\"advice\">{}</p>\n</div>\n</article>",
        esc(&u.meaning),
        esc(&u.advice)
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::summary;
    use super::super::tests::section_of;
    use super::*;
    use crate::view;

    /// Each thing that could not be read is told whole, once, under "Could not be read", where
    /// the band's count leads and counted as it counts them: a cause by its own message, the
    /// person's own first and marked, and every other reading that failed, of the event level or
    /// a download, as the text says it, its words, what its source said and its command. With
    /// nothing that could not be read there is neither the section nor the count, so neither says
    /// that everything was read; only the section's anchor stands, with no words, so the link
    /// `store.view_sections` names lands in place.
    #[test]
    fn what_could_not_be_read_is_told_whole_once_where_the_band_s_count_leads() {
        let now = 1_800_000_000;
        let calm = v1::Status {
            answered_at: now,
            ..crate::headline::tests::calm()
        };
        let summary = |r: &v1::Status| summary(r, &view::Answers::none(), now).unwrap();
        let page = summary(&calm);
        let body = &page[page.find("</style>").unwrap()..];
        assert!(
            body.matches(&format!("id=\"{NOT_READ}\"")).count() == 1
                && body.contains(&format!("<div id=\"{NOT_READ}\"></div>"))
                && !body.contains("could not be read"),
            "{body}"
        );
        // A reading that failed of each kind: the event level records nothing, it lost program
        // starts since the latest check, a download failed.
        let level = |state: v1::CollectorState, lost: u64| {
            let mut r = calm.clone();
            r.event_level = Some(v1::EventLevel {
                state: state as i32,
                said_text: Some("an invented <line>".to_string()),
                lost: Some(v1::Span {
                    since_check: lost,
                    ..Default::default()
                }),
                ..Default::default()
            });
            r
        };
        let mut download = calm.clone();
        download.vulnerability_data = Some(v1::VulnerabilityData {
            feeds: vec![v1::FeedState {
                source: "OSV".to_string(),
                ecosystem: "npm".to_string(),
                outcome: v1::FeedOutcome::Failed as i32,
                read_at: Some(now - 600),
                ..Default::default()
            }],
            ..Default::default()
        });
        for mut r in [
            level(v1::CollectorState::Failing, 0),
            level(v1::CollectorState::Running, 4),
            download,
        ] {
            // Two causes, the one the person cannot fix first in the status.
            r.not_covered = vec![
                v1::Uncovered {
                    id: "tried-again".to_string(),
                    who: "nothing".to_string(),
                    title: "Another invented title.".to_string(),
                    fault: true,
                    count: 1,
                    ..Default::default()
                },
                v1::Uncovered {
                    id: "not-permitted".to_string(),
                    who: YOU.to_string(),
                    title: "An invented title.".to_string(),
                    meaning: "What it invented means.".to_string(),
                    advice: "What to do, invented.".to_string(),
                    fault: true,
                    count: 1,
                    examples: vec![v1::UncoveredExample {
                        name_text: "~/.invented".to_string(),
                        reason_text: Some("Permission <denied>".to_string()),
                    }],
                    ..Default::default()
                },
            ];
            let page = summary(&r);
            let at = |id: &str| page.find(&format!("<section id=\"{id}\"")).unwrap();
            assert!(
                page.contains(&format!(
                    "<a href=\"#{NOT_READ}\">3 things could not be read, 1 you can fix</a>"
                )),
                "{page}"
            );
            assert!(at("this-mac") < at(NOT_READ), "{page}");
            let section = section_of(&page, NOT_READ);
            // The section counts what it tells as the band does, the person's own first.
            assert!(
                section.contains("<span class=\"n\">3 things · 1 you can fix</span>"),
                "{section}"
            );
            let at = |id: &str| section.find(&format!("id=\"{id}\"")).unwrap();
            assert!(at("not-permitted") < at("tried-again"), "{section}");
            let told = crate::overview::told(&r, &TERMINAL);
            let failed: Vec<&crate::overview::Fault> = (told.faults.iter())
                .filter(|f| f.about() == Of::Reading)
                .collect();
            assert_eq!(failed.len(), 1, "{page}");
            for f in failed {
                let (words, said, _, command, _) = f.parts();
                for piece in [
                    Some(esc(words)),
                    said.map(crate::secrets::quoted_html),
                    command.map(esc),
                ]
                .into_iter()
                .flatten()
                {
                    assert_eq!(section.matches(&piece).count(), 1, "{piece}: {section}");
                }
            }
            let cause = &section[section.find("id=\"not-permitted\"").unwrap()..];
            for piece in [
                ">You can fix</p>",
                "<h3>An invented title.</h3>",
                "<bdi class=\"src\">~/.invented</bdi>: <bdi class=\"src\">Permission &lt;denied&gt;</bdi>",
                "What it invented means.",
                "What to do, invented.",
            ] {
                assert!(cause.contains(piece), "{piece}: {cause}");
            }
        }
    }

    /// The count says how many things could not be read, not how many causes: a cause about a
    /// hundred servers is a hundred, as its title says, in the band and in the section alike, and
    /// a cause that counts nothing is one.
    #[test]
    fn a_cause_of_a_hundred_servers_is_counted_as_a_hundred() {
        let now = 1_800_000_000;
        let mut r = v1::Status {
            answered_at: now,
            ..crate::headline::tests::calm()
        };
        r.not_covered = vec![
            v1::Uncovered {
                id: "servers-not-opened".to_string(),
                who: YOU.to_string(),
                title: "100 servers could not be opened at the last server check.".to_string(),
                fault: true,
                count: 100,
                ..Default::default()
            },
            v1::Uncovered {
                id: "counts-nothing".to_string(),
                who: "nothing".to_string(),
                fault: true,
                ..Default::default()
            },
        ];
        let page = summary(&r, &view::Answers::none(), now).unwrap();
        assert!(
            page.contains(&format!(
                "<a href=\"#{NOT_READ}\">101 things could not be read, 100 you can fix</a>"
            )) && section_of(&page, NOT_READ)
                .contains("<span class=\"n\">101 things · 100 you can fix</span>"),
            "{page}"
        );
    }

    /// The page of this Mac says that something could not be read, counted as the band counts it
    /// and leading to where the summary tells it, also when no kind's row on it does: a list of
    /// vulnerabilities not updated and program starts that were lost are about no kind of place.
    /// With nothing that could not be read it says nothing of it.
    #[test]
    fn the_page_of_this_mac_says_what_could_not_be_read_when_no_kind_s_row_does() {
        let now = 1_800_000_000;
        let calm = v1::Status {
            answered_at: now,
            ..crate::headline::tests::calm()
        };
        let this_mac = |r: &v1::Status| {
            let pages = view::pages(r, &view::Answers::none(), now).unwrap();
            let name = format!("{}/{}.html", view::DETAILS, super::super::THIS_MAC);
            pages.into_iter().find(|(n, _)| *n == name).unwrap().1
        };
        assert!(!this_mac(&calm).contains("<p class=\"meta fault\">"));
        let mut r = calm.clone();
        r.not_covered = vec![v1::Uncovered {
            id: "vulnerability-data-old".to_string(),
            who: "nothing".to_string(),
            fault: true,
            count: 1,
            ..Default::default()
        }];
        r.event_level = Some(v1::EventLevel {
            state: v1::CollectorState::Running as i32,
            lost: Some(v1::Span {
                since_check: 4,
                ..Default::default()
            }),
            ..Default::default()
        });
        let page = this_mac(&r);
        let band = summary(&r, &view::Answers::none(), now).unwrap();
        assert!(
            band.contains(&format!(
                "<p class=\"sub fault\">! <a href=\"#{NOT_READ}\">2 things could not be read</a></p>"
            )),
            "{band}"
        );
        assert!(
            page.contains(&format!(
                "<p class=\"meta fault\">! <a href=\"../{}#{NOT_READ}\">2 things could not be read</a></p>",
                view::SUMMARY
            )),
            "{page}"
        );
    }
}
