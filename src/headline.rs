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

/// The headline and its reasons by the schema's rule, in its order. It is never calmer than a
/// section of the message: calm needs a live watcher with no failure standing, this Mac watched
/// with no fault, no cause that is a fault (`Uncovered.fault`), an event level that runs or is
/// not installed, and no check that died. A limit of this version is none of them: a reading
/// that failed or a machine not reached keeps it from calm only as a fault.
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
            // A live watcher the status itself describes: `live` and `watching` are two reads,
            // and a watcher that left between them leaves `live` alone.
            !m.live || s.watching.as_ref().is_none_or(|w| !w.failed.is_empty()),
        ),
        (B::ThisMac, in_part),
        (B::NotCovered, s.not_covered.iter().any(|u| u.fault)),
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

    /// A fresh status with nothing to look at, this Mac watched by a live watcher, and no fault:
    /// the one calm is for.
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
    /// is calm; a limit, however it failed, is none; and the rule's order holds: no `needs_a_look`
    /// is unknown, a finding wins over no check, no check over stale, stale over in part, and a
    /// state not known over in part.
    #[test]
    fn calm_only_when_no_fault_stands_and_the_rule_keeps_its_order() {
        assert_eq!(headline(&calm()), (Headline::Calm, vec![]));
        let alone: [(B, Change); 14] = [
            (B::Watcher, |s| mac(s).live = false),
            (B::Watcher, |s| {
                s.watching.as_mut().unwrap().failed = vec![v1::WatcherFailure::default()]
            }),
            // Live, and no watcher the status describes: it left between the two reads.
            (B::Watcher, |s| s.watching = None),
            (B::ThisMac, |s| {
                mac(s).state = ThisMacState::WatchedInPart as i32
            }),
            // A fault, whatever its class says.
            (B::NotCovered, |s| {
                s.not_covered = vec![v1::Uncovered {
                    class: v1::Cause::NotGiven as i32,
                    fault: true,
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
            // A reading that failed and is a limit, a class this build does not know, readings
            // counted as failed and a machine not reached: none is a fault on its own.
            (B::Unspecified, |s| {
                s.not_covered = vec![v1::Uncovered {
                    class: v1::Cause::Failed as i32,
                    ..Default::default()
                }]
            }),
            (B::Unspecified, |s| {
                s.not_covered = vec![v1::Uncovered {
                    class: 99,
                    ..Default::default()
                }]
            }),
            (B::Unspecified, |s| {
                let c = s.coverage.as_mut().unwrap();
                (c.failed, c.unreached_total) = (1, 1);
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
        for (_, change) in &alone[..8] {
            change(&mut all);
        }
        assert_eq!(
            headline(&all).1,
            [
                B::Watcher,
                B::ThisMac,
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
