//! The answer of a status in one word, `Status.headline`, and what keeps a fresh answer with
//! nothing to look at from calm, `Status.headline_because`: one rule, the schema's (`Headline` in
//! `status.proto`), computed once at the end of `status::message` from the message alone, so it
//! rests on exactly what is printed. The terminal (`overview::answer`) and the pages
//! (`pages::state`) pick their words and glyphs by it and decide nothing of their own.

use crate::contract::v1::{
    self, CollectorState, Headline, HeadlineBecause as B, Status, ThisMacState,
};

/// The message with its headline, computed from the message alone.
pub(crate) fn headed(mut out: Status) -> Status {
    let (headline, because) = headline(&out);
    out.headline = headline as i32;
    out.headline_because = because.into_iter().map(|b| b as i32).collect();
    out
}

/// Whether a cause of what is not covered is a failure, as its class says: a reading or a
/// download that was tried and did not succeed, whoever can fix it. A class this build does not
/// know, or none, is read as a failure, as the schema says.
pub(crate) fn is_failure(u: &v1::Uncovered) -> bool {
    !matches!(
        v1::Cause::try_from(u.class),
        Ok(v1::Cause::NoReader | v1::Cause::NotGiven)
    )
}

/// The headline and its reasons by the schema's rule, in its order. It is never calmer than a
/// section of the message: calm needs a live watcher with no failure standing, this Mac watched
/// whole, no reading failed and no machine left unreached, no cause that is a failure, an event
/// level that runs or is not installed, and no check that died.
pub(crate) fn headline(s: &Status) -> (Headline, Vec<B>) {
    let Some(look) = &s.needs_a_look else {
        return (Headline::Unknown, Vec::new());
    };
    if look.total > 0 {
        return (Headline::NeedsALook, Vec::new());
    }
    let Some(m) = s.this_mac.as_ref().filter(|m| m.checked_at.is_some()) else {
        return (Headline::NotChecked, Vec::new());
    };
    if !m.fresh {
        return (Headline::Stale, Vec::new());
    }
    let in_part = match ThisMacState::try_from(m.state) {
        Ok(ThisMacState::Watched) => false,
        Ok(ThisMacState::WatchedInPart) => true,
        _ => return (Headline::Unknown, Vec::new()),
    };
    let level = |l: &v1::EventLevel| {
        l.state != CollectorState::Running as i32 && l.state != CollectorState::NotInstalled as i32
    };
    let because: Vec<B> = [
        (
            B::Watcher,
            !m.live || s.watching.as_ref().is_some_and(|w| !w.failed.is_empty()),
        ),
        (B::ThisMac, in_part),
        (
            B::Coverage,
            s.coverage
                .as_ref()
                .is_some_and(|c| c.failed > 0 || c.unreached_total > 0),
        ),
        (B::NotCovered, s.not_covered.iter().any(is_failure)),
        (B::EventLevel, s.event_level.as_ref().is_some_and(level)),
        (
            B::LastRun,
            s.last_run
                .as_ref()
                .is_some_and(|l| l.finished_at.is_none() && !s.running),
        ),
    ]
    .into_iter()
    .filter_map(|(b, holds)| holds.then_some(b))
    .collect();
    match because.is_empty() {
        true => (Headline::Calm, because),
        false => (Headline::InPart, because),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One change to a status.
    type Change = fn(&mut Status);

    /// A fresh status with nothing to look at, this Mac watched whole by a live watcher, and
    /// nothing failed: the one calm is for.
    fn calm() -> Status {
        Status {
            needs_a_look: Some(v1::NeedsALook::default()),
            this_mac: Some(v1::ThisMac {
                state: ThisMacState::Watched as i32,
                live: true,
                checked_at: Some(1_800_000_000),
                fresh: true,
                ..Default::default()
            }),
            watching: Some(v1::Watcher::default()),
            coverage: Some(v1::CoverageSummary::default()),
            event_level: Some(v1::EventLevel {
                state: CollectorState::Running as i32,
                ..Default::default()
            }),
            last_run: Some(v1::CheckMark {
                finished_at: Some(1_800_000_000),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn mac(s: &mut Status) -> &mut v1::ThisMac {
        s.this_mac.as_mut().unwrap()
    }

    /// Each reason alone keeps a fresh answer with nothing to look at from calm and is named; none
    /// is calm; and the rule's order holds: no `needs_a_look` is unknown, a finding wins over no
    /// check, no check over stale, stale over in part, and a state not known over in part.
    #[test]
    fn calm_only_when_no_section_of_the_status_says_otherwise_and_the_rule_keeps_its_order() {
        assert_eq!(headline(&calm()), (Headline::Calm, vec![]));
        let alone: [(B, Change); 13] = [
            (B::Watcher, |s| mac(s).live = false),
            (B::Watcher, |s| {
                s.watching.as_mut().unwrap().failed = vec![v1::WatcherFailure::default()]
            }),
            (B::ThisMac, |s| {
                mac(s).state = ThisMacState::WatchedInPart as i32
            }),
            (B::Coverage, |s| s.coverage.as_mut().unwrap().failed = 1),
            (B::Coverage, |s| {
                s.coverage.as_mut().unwrap().unreached_total = 1
            }),
            (B::NotCovered, |s| {
                s.not_covered = vec![v1::Uncovered {
                    class: v1::Cause::Failed as i32,
                    ..Default::default()
                }]
            }),
            // A class this build does not know is a failure.
            (B::NotCovered, |s| {
                s.not_covered = vec![v1::Uncovered {
                    class: 99,
                    ..Default::default()
                }]
            }),
            (B::EventLevel, |s| {
                s.event_level.as_mut().unwrap().state = CollectorState::Failing as i32
            }),
            (B::EventLevel, |s| {
                s.event_level.as_mut().unwrap().state = CollectorState::Refused as i32
            }),
            (B::LastRun, |s| {
                s.last_run.as_mut().unwrap().finished_at = None
            }),
            // What is not a failure keeps it calm: these are checked to stay calm below.
            (B::Unspecified, |s| {
                s.event_level.as_mut().unwrap().state = CollectorState::NotInstalled as i32
            }),
            (B::Unspecified, |s| {
                s.not_covered = vec![v1::Uncovered {
                    class: v1::Cause::NoReader as i32,
                    ..Default::default()
                }]
            }),
            (B::Unspecified, |s| {
                s.last_run.as_mut().unwrap().finished_at = None;
                s.running = true;
            }),
        ];
        for (i, (because, change)) in alone.iter().enumerate() {
            let mut s = calm();
            change(&mut s);
            let expected = match because {
                B::Unspecified => (Headline::Calm, vec![]),
                b => (Headline::InPart, vec![*b]),
            };
            assert_eq!(headline(&s), expected, "{i}");
            // `headed` writes what the rule gives into the message.
            let s = headed(s);
            assert_eq!(
                (s.headline, s.headline_because),
                (
                    expected.0 as i32,
                    expected.1.iter().map(|b| *b as i32).collect()
                ),
                "{i}"
            );
        }
        // Every reason at once is named in the schema's order.
        let mut all = calm();
        for (_, change) in &alone[..10] {
            change(&mut all);
        }
        assert_eq!(
            headline(&all).1,
            [
                B::Watcher,
                B::ThisMac,
                B::Coverage,
                B::NotCovered,
                B::EventLevel,
                B::LastRun
            ]
        );
        // Stale wins over every reason, and a finding over them too.
        let mut old = all.clone();
        mac(&mut old).fresh = false;
        assert_eq!(headline(&old), (Headline::Stale, vec![]));
        let mut found = all.clone();
        found.needs_a_look.as_mut().unwrap().total = 1;
        assert_eq!(headline(&found), (Headline::NeedsALook, vec![]));
        // A state not known wins over every reason; stale wins over it; no finished check over
        // stale; a finding over all of them; and no `needs_a_look` over a finding.
        mac(&mut all).state = ThisMacState::Unspecified as i32;
        assert_eq!(headline(&all), (Headline::Unknown, vec![]));
        mac(&mut all).state = 99;
        assert_eq!(headline(&all).0, Headline::Unknown);
        mac(&mut all).fresh = false;
        assert_eq!(headline(&all), (Headline::Stale, vec![]));
        mac(&mut all).checked_at = None;
        assert_eq!(headline(&all), (Headline::NotChecked, vec![]));
        all.this_mac = None;
        assert_eq!(headline(&all).0, Headline::NotChecked);
        all.needs_a_look.as_mut().unwrap().total = 1;
        assert_eq!(headline(&all), (Headline::NeedsALook, vec![]));
        all.needs_a_look = None;
        assert_eq!(headline(&all), (Headline::Unknown, vec![]));
    }

    /// A check that has written its end and still holds its lock while it tidies the store is not
    /// said to run, and every status carries the headline the rule gives its own message.
    #[test]
    fn a_finished_check_is_not_running_and_a_status_carries_its_own_headline() {
        let dir = crate::common::Scratch::new("headline-running");
        let store = dir.join("store.db");
        let conn = crate::store::open_or_make(&store).unwrap();
        let at = 1_800_000_000;
        let said = |now: i64| {
            let st = crate::status::state(&conn, &dir, now).unwrap();
            crate::status::message(Some(&conn), Some(&st), true, &store, now).unwrap()
        };
        crate::store::journal_note(&conn, at, "run-1", "run_started", "").unwrap();
        let running = said(at + 1);
        assert!(running.running);
        assert_eq!(running.headline, Headline::NotChecked as i32);
        crate::store::journal_note(&conn, at + 2, "run-1", "run_finished", "").unwrap();
        let finished = said(at + 3);
        assert!(!finished.running);
        let (headline, because) = headline(&finished);
        assert_eq!(
            (finished.headline, finished.headline_because),
            (headline as i32, because.iter().map(|b| *b as i32).collect())
        );
        let none = crate::status::message(None, None, false, &dir.join("none.db"), at).unwrap();
        assert_eq!(none.headline, Headline::Unknown as i32);
    }
}
