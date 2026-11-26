//! The core's hourly full checks, alongside its watcher. launchd only supervises the process.
//! Each check is the same binary's `run` command: the store remains the only seam.

use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

/// How often a full check starts, in seconds.
pub const EVERY: i64 = 60 * 60;
/// How soon a full check that could not get the store, another run or process holding it, is
/// tried again: within minutes, not at the next hour.
const RETRY: i64 = 5 * 60;
/// How long a full check may run, in awake time: a sleep while it runs does not end it.
const LIMIT: Duration = Duration::from_secs(30 * 60);
pub const CHECK_ARG: &str = "--background-check";
/// The most of a check's output the watcher keeps, to read the `Failure` it prints: the longest
/// text the cut of secrets reads (`secrets::LINE_CAP`), as a detail longer is withheld whole.
const SAID_CAP: u64 = crate::secrets::LINE_CAP as u64;

pub fn command(binary: &std::path::Path) -> Command {
    let mut command = Command::new(binary);
    command
        .arg(CHECK_ARG)
        .arg(std::process::id().to_string())
        .arg("run")
        .arg("--json");
    command
}

/// Arm the check before it can read anything. The write end of stdin belongs only to the
/// watcher. launchd stops the watcher's group, so this separate group watches the pipe too.
pub fn supervise(parent: &str) -> io::Result<()> {
    // SAFETY: these queries take no pointers and return the calling process's identity.
    let (pid, group, actual_parent) = unsafe { (libc::getpid(), libc::getpgrp(), libc::getppid()) };
    if group != pid || actual_parent == 1 || parent.parse() != Ok(actual_parent) {
        return Err(io::Error::other(
            "the full check has no supervising watcher",
        ));
    }
    // SAFETY: fstat writes only into this initialized structure for the given fd.
    let mut input: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(libc::STDIN_FILENO, &mut input) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if input.st_mode & libc::S_IFMT != libc::S_IFIFO {
        return Err(io::Error::other("the full check has no lifetime pipe"));
    }
    let mut stdin = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    if poll(&mut stdin, 0)? {
        return Err(io::Error::other(
            "the full check's watcher has already stopped",
        ));
    }
    std::thread::Builder::new().spawn(move || {
        let deadline = Instant::now() + LIMIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            // A timeout is only a moment to look at the awake time again: poll(2) does not say
            // whether its timeout counts the time the Mac slept.
            match poll(&mut stdin, left.as_millis() as i32) {
                Ok(false) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                _ => break,
            }
        }
        // SAFETY: this process leads the group for this check and its tools.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    })?;
    Ok(())
}

fn poll(fd: &mut libc::pollfd, timeout_ms: i32) -> io::Result<bool> {
    // SAFETY: a single initialized pollfd is alive for the duration of this call.
    let ready = unsafe { libc::poll(fd, 1, timeout_ms) };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ready != 0)
}

pub struct Checks {
    command: Command,
    running: Option<Running>,
    next: i64,
    last: i64,
    /// What the latest check printed, up to `SAID_CAP`, sent once its output closes (`kept`).
    said: Option<Receiver<Vec<u8>>>,
    /// How the latest check failed and when it started, while its reason may still come: a
    /// tool that left its group can hold its output open after it ended.
    late: Option<(ExitStatus, Instant)>,
}

struct Running {
    child: Child,
    since: Instant,
}

impl Checks {
    pub fn new(mut command: Command) -> Self {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        Self {
            command,
            running: None,
            next: 0,
            last: 0,
            said: None,
            late: None,
        }
    }

    /// Called by the watcher, also while it waits for the run lock. Wall time notices a
    /// missed hour after sleep; scheduling from now coalesces all missed hours into one.
    /// `awake` is `Instant::now()`, which the limit of a running check is counted on.
    pub fn tick(&mut self, now: i64, awake: Instant) -> Option<Result<(), String>> {
        if now < self.last {
            self.next = now;
        }
        self.last = now;
        if let Some(running) = &mut self.running {
            match running.finished() {
                Ok(Some(status)) => {
                    let (since, expired) = (running.since, Self::expired(running.since, awake));
                    self.running = None;
                    if status.code() == Some(crate::EXIT_RUN_IN_PROGRESS.into()) {
                        self.next = self.next.min(now.saturating_add(RETRY));
                        return None;
                    }
                    if status.success() || expired {
                        return Some(if status.success() {
                            Ok(())
                        } else {
                            Err("the full check exceeded 30 minutes and was stopped".into())
                        });
                    }
                    // Said at once; its reason follows when what it printed comes (`late_reason`).
                    self.late = Some((status, since));
                    return Some(Err(format!("the full check ended with {status}")));
                }
                Err(e) => {
                    self.running = None;
                    return Some(Err(format!("the full check could not be waited for: {e}")));
                }
                Ok(None) => {}
            }
            if Self::expired(running.since, awake) {
                self.running = None;
                return Some(Err(
                    "the full check exceeded 30 minutes and was stopped".into()
                ));
            }
        } else if now >= self.next {
            self.next = now.saturating_add(EVERY);
            match self.command.spawn() {
                Ok(mut child) => {
                    let (sent, said) = mpsc::channel();
                    let out = child.stdout.take();
                    // A reader that cannot start closes the check's output: the check cannot
                    // print, and is said by how it ended.
                    let _ = std::thread::Builder::new()
                        .spawn(move || sent.send(out.map(kept).unwrap_or_default()));
                    (self.said, self.late) = (Some(said), None);
                    self.running = Some(Running {
                        child,
                        since: awake,
                    });
                }
                Err(e) => return Some(Err(format!("the full check could not start: {e}"))),
            }
        }
        None
    }

    /// The failure the latest check's tick said, in the check's own words once what it printed
    /// has come: the same failure, its text now with the reason, or none when the check said it
    /// committed (`reason`). Asked after every tick, it never waits, and stops expecting a
    /// reason when the check's time is up.
    pub fn late_reason(&mut self, awake: Instant) -> Option<Result<(), String>> {
        let (status, since) = self.late?;
        let said = match self.said.as_ref()?.try_recv() {
            Err(TryRecvError::Empty) if !Self::expired(since, awake) => return None,
            said => said.ok().and_then(|said| reason(&said)),
        };
        (self.said, self.late) = (None, None);
        Some(said?.map_err(|why| format!("the full check failed ({status}): {why}")))
    }

    fn expired(since: Instant, awake: Instant) -> bool {
        awake.saturating_duration_since(since) >= LIMIT
    }
}

/// The first `SAID_CAP` bytes a check printed, the rest read and dropped to the end, so the check
/// never waits on a full pipe however much it prints. It runs on a thread of its own.
fn kept(mut out: impl Read) -> Vec<u8> {
    let mut said = Vec::new();
    let _ = (&mut out).take(SAID_CAP).read_to_end(&mut said);
    let _ = io::copy(&mut out, &mut io::sink());
    said
}

/// Why a check failed in its own words: the code of the `Failure` it printed and what that
/// quoted, cut for secrets and then at most `TEXT_CAP` characters of it, so a cap never leaves
/// part of a secret the cut would not know. It is data: only the code is read, and a check that
/// committed and could not read its answer back (`answer_unreadable`, `unread` in `main.rs`)
/// finished, which is no failure.
fn reason(said: &[u8]) -> Option<Result<(), String>> {
    let failure: crate::contract::v1::Failure = serde_json::from_slice(said).ok()?;
    let error = failure.errors.first()?;
    if error.code == "answer_unreadable" {
        return Some(Ok(()));
    }
    Some(Err(match error.detail_text.as_deref() {
        Some(detail) => {
            let cut = crate::secrets::said_within(
                &crate::contract::unescape(detail),
                crate::status::TEXT_CAP,
            );
            format!("{}: {}", error.code, crate::contract::unescape(&cut))
        }
        None => error.code.clone(),
    }))
}

impl Running {
    fn finished(&mut self) -> io::Result<Option<ExitStatus>> {
        // SAFETY: initialized signal info is written by waitid. WNOWAIT keeps the child's
        // pid reserved until Drop so it can still stop any tools after an unexpected exit.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(error);
        }
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        self.stop_group();
        self.child.wait().map(Some)
    }

    fn stop_group(&self) {
        // SAFETY: this unreaped child heads the private group made by process_group(0).
        unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) };
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.finished().is_ok_and(|status| status.is_none()) {
            self.stop_group();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script]);
        cmd
    }

    /// How a check ended, as the watcher records it in the end: a reason that comes after the
    /// tick that said the failure replaces its text.
    fn finished(checks: &mut Checks, now: i64) -> Result<(), String> {
        let end = Instant::now() + Duration::from_secs(10);
        let result = loop {
            if let Some(result) = checks.tick(now, Instant::now()) {
                break result;
            }
            assert!(Instant::now() < end, "the invented check did not finish");
            std::thread::sleep(Duration::from_millis(10));
        };
        while checks.late.is_some() {
            if let Some(late) = checks.late_reason(Instant::now()) {
                return late;
            }
            assert!(
                Instant::now() < end,
                "the invented check's output did not close"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        result
    }

    #[test]
    fn full_checks_start_at_once_then_hourly_and_sleep_creates_one_check_without_a_burst() {
        let mut checks = Checks::new(command("exit 0"));
        assert!(checks.tick(10, Instant::now()).is_none());
        assert!(checks.running.is_some());
        finished(&mut checks, 10).unwrap();
        assert!(checks.tick(3609, Instant::now()).is_none());
        assert!(checks.running.is_none());
        assert!(checks.tick(3610, Instant::now()).is_none());
        assert!(checks.running.is_some());
        finished(&mut checks, 3610).unwrap();
        assert!(checks.tick(20000, Instant::now()).is_none());
        assert!(checks.running.is_some());
        finished(&mut checks, 20000).unwrap();
        assert!(checks.tick(20000, Instant::now()).is_none());
        assert!(checks.running.is_none());
        assert!(checks.tick(23599, Instant::now()).is_none());
        assert!(checks.running.is_none());
        assert!(checks.tick(23600, Instant::now()).is_none());
        assert!(checks.running.is_some());
        finished(&mut checks, 23600).unwrap();
    }

    #[test]
    fn a_failed_check_is_reported_and_start_failure_waits_until_the_next_hour() {
        let mut checks = Checks::new(command("exit 7"));
        assert!(finished(&mut checks, 10).unwrap_err().contains('7'));
        assert!(checks.tick(11, Instant::now()).is_none());
        assert!(checks.running.is_none());
        let mut checks = Checks::new(Command::new("/no/such/immunity-test-tool"));
        assert!(
            checks
                .tick(10, Instant::now())
                .unwrap()
                .unwrap_err()
                .contains("could not start")
        );
        assert!(checks.tick(3609, Instant::now()).is_none());
        assert!(checks.tick(3610, Instant::now()).unwrap().is_err());
    }

    /// A `Failure` as `immunity run --json` prints it, with `detail` as the check said it, and
    /// none when it is empty.
    fn failure_json(detail: &str) -> String {
        let mut error = crate::answer::error("run_failed", "the run failed", "", "");
        error.detail_text = (!detail.is_empty()).then(|| crate::secrets::said(detail));
        serde_json::to_string(&crate::contract::v1::Failure {
            operation: "run".into(),
            ok: false,
            errors: vec![error],
        })
        .unwrap()
    }

    #[test]
    fn a_full_check_that_fails_and_says_why_leaves_its_code_and_reason_beside_how_it_ended() {
        let dir = crate::common::Scratch::new("check-says-why");
        // An invented core: it prints its failure only when asked for the machine form.
        let core = dir.join("immunity");
        let script = "#!/bin/sh\ncase \" $* \" in *\" --json \"*) printf '%s\\n' \"$FAILURE\";; esac\nexit 1\n";
        std::fs::write(&core, script).unwrap();
        std::fs::set_permissions(&core, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        // The backslash is the check's own, kept once: the status writes it `\u{5c}` once.
        for (detail, why) in [
            (r"held at C:\store", r": run_failed: held at C:\store"),
            ("", ": run_failed"),
        ] {
            let mut cmd = super::command(&core);
            cmd.env("FAILURE", failure_json(detail));
            let said = finished(&mut Checks::new(cmd), 10).unwrap_err();
            assert_eq!(said, format!("the full check failed (exit status: 1){why}"));
        }
    }

    #[test]
    fn a_check_that_prints_past_the_cap_is_not_held_up_and_nothing_past_the_cap_is_kept() {
        let printing = |json: String| {
            let mut cmd = command("printf '%s\\n' \"$1\"; exit 1");
            cmd.arg("check").arg(json);
            Checks::new(cmd)
        };
        // A reason longer than status keeps is kept to `TEXT_CAP` characters.
        let long = "x".repeat(4 * crate::status::TEXT_CAP);
        let why = finished(&mut printing(failure_json(&long)), 10).unwrap_err();
        let capped = crate::status::capped(long);
        assert_eq!(
            why,
            format!("the full check failed (exit status: 1): run_failed: {capped}")
        );
        // More than a pipe holds and than the watcher reads, a failure after blanks: the check is
        // not held up, and what went past the cap is not kept.
        let past = " ".repeat(4 * SAID_CAP as usize) + &failure_json("held");
        let why = finished(&mut printing(past), 10).unwrap_err();
        assert_eq!(why, "the full check ended with exit status: 1");
    }

    #[test]
    fn a_secret_the_cap_of_a_reason_would_end_inside_is_cut_whole_before_the_cap() {
        // A check's detail with a token across the cap, as no check of the core prints it.
        let token = ["gh", "p_", "Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS2aE7u"].concat();
        let mut failure: serde_json::Value = serde_json::from_str(&failure_json("x")).unwrap();
        failure["errors"][0]["detail_text"] = format!("{} ?t={token}", "y".repeat(240)).into();
        let why = reason(failure.to_string().as_bytes()).unwrap().unwrap_err();
        assert_eq!(why, format!("run_failed: {} ?t=…", "y".repeat(240)));
    }

    #[test]
    fn a_failed_check_whose_tool_keeps_its_output_open_is_recorded_on_the_tick_it_ended() {
        let dir = crate::common::Scratch::new("check-output-held");
        let pid_file = dir.join("tool");
        // Job control puts the tool in a group of its own, which stopping the check's misses, so
        // the check's output stays open after it ends: here until the tool prints the check's
        // failure late, or without end.
        let late = "(/bin/sleep 0.5; printf '%s\\n' \"$2\")";
        let mut checks = [late, "/usr/bin/yes"].map(|tool| {
            let mut cmd = command(&format!("set -m; {tool} & echo $! > \"$1\"; exit 1"));
            cmd.arg("check").arg(&pid_file).arg(failure_json("held"));
            Checks::new(cmd)
        });
        let (said, why) = mpsc::channel();
        let turns = std::thread::spawn(move || {
            let ended = |checks: &mut Checks| {
                let start = Instant::now();
                checks.tick(10, start);
                while checks.running.is_some() {
                    if let Some(result) = checks.tick(10, Instant::now()) {
                        return (start, result);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                panic!("the check ended on no tick")
            };
            let [late, endless] = &mut checks;
            let (_, result) = ended(late);
            let mut reason = None;
            while reason.is_none() {
                reason = late.late_reason(Instant::now());
                std::thread::sleep(Duration::from_millis(10));
            }
            let (start, endless_result) = ended(endless);
            let early = endless.late_reason(Instant::now());
            let given_up = endless.late_reason(start + LIMIT);
            let _ = said.send((
                result,
                reason,
                endless_result,
                early,
                given_up,
                endless.late,
            ));
        });
        // A turn that waits on the check's output fails here instead of hanging.
        let why = why.recv_timeout(Duration::from_secs(10));
        if let Some(tool) = std::fs::read_to_string(&pid_file)
            .ok()
            .and_then(|p| p.trim().parse().ok())
        {
            // SAFETY: the invented tool this test started.
            unsafe { libc::kill(tool, libc::SIGKILL) };
        }
        let (result, reason, endless_result, early, given_up, late) = match why {
            Ok(why) => why,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("a turn waited on the check's output"),
            Err(_) => std::panic::resume_unwind(turns.join().unwrap_err()),
        };
        let ended = Err("the full check ended with exit status: 1".to_string());
        assert_eq!(result, ended);
        let failed = "the full check failed (exit status: 1): run_failed: held";
        assert_eq!(reason, Some(Err(failed.to_string())));
        assert_eq!(endless_result, ended);
        assert_eq!((early, given_up, late), (None, None, None));
    }

    #[test]
    fn a_reason_still_expected_is_never_taken_from_the_next_check() {
        let dir = crate::common::Scratch::new("check-next-said");
        // The first check fails with its output held open; the next, started at once by a clock
        // moved back, prints a failure and succeeds.
        let script = "if [ -f \"$1\" ]; then printf '%s\\n' \"$2\"; exit 0; fi; : > \"$1\"; \
                      set -m; /bin/sleep 2 & exit 1";
        let mut cmd = command(script);
        cmd.arg("check")
            .arg(dir.join("ran"))
            .arg(failure_json("held"));
        let mut checks = Checks::new(cmd);
        let end = Instant::now() + Duration::from_secs(10);
        while checks.tick(10_000, Instant::now()).is_none() {
            assert!(Instant::now() < end, "the invented check did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(checks.late.is_some());
        assert_eq!(finished(&mut checks, 10), Ok(()));
    }

    #[test]
    fn a_full_check_that_fails_and_prints_nothing_readable_is_said_by_how_it_ended() {
        for script in ["echo '{\"not\": \"a failure'; exit 3", "echo '{}'; exit 3"] {
            let why = finished(&mut Checks::new(command(script)), 10).unwrap_err();
            assert_eq!(why, "the full check ended with exit status: 3");
        }
    }

    #[test]
    fn a_full_check_that_could_not_get_the_store_is_no_failure_and_is_tried_again_within_minutes() {
        let reaped = |checks: &mut Checks, now: i64| {
            let end = Instant::now() + Duration::from_secs(10);
            while checks.running.is_some() {
                assert!(checks.tick(now, Instant::now()).is_none());
                assert!(Instant::now() < end, "the skipped check was not reaped");
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        let mut checks = Checks::new(command("exit 4"));
        checks.tick(10, Instant::now());
        reaped(&mut checks, 100);
        // Five minutes after the watcher saw it end, as the documents say, not after its start.
        assert!(checks.tick(399, Instant::now()).is_none());
        assert!(checks.running.is_none());
        assert!(checks.tick(400, Instant::now()).is_none());
        assert!(checks.running.is_some());
        reaped(&mut checks, 400);
        // A check already due sooner, here by a clock moved back, is not put off by the retry.
        let mut checks = Checks::new(command("exit 4"));
        checks.tick(10_000, Instant::now());
        reaped(&mut checks, 5_000);
        assert!(checks.tick(5_000, Instant::now()).is_none());
        assert!(checks.running.is_some());
        reaped(&mut checks, 5_000);
    }

    #[test]
    fn a_hung_check_is_stopped_after_thirty_minutes_awake_and_reaped_before_the_next_check() {
        let mut checks = Checks::new(command("exec /bin/sleep 60"));
        let start = Instant::now();
        checks.tick(10, start);
        let pid = checks.running.as_ref().unwrap().child.id() as libc::pid_t;
        let awake = |secs| start + Duration::from_secs(secs);
        assert!(checks.tick(1809, awake(1799)).is_none());
        assert_eq!(checks.running.as_ref().unwrap().child.id() as i32, pid);
        assert!(
            checks
                .tick(1810, awake(1800))
                .unwrap()
                .unwrap_err()
                .contains("30 minutes")
        );
        assert!(checks.running.is_none());
        // SAFETY: signal 0 only asks whether the child still exists.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert!(checks.tick(3609, awake(3599)).is_none());
        assert!(checks.running.is_none());
        assert!(checks.tick(3610, awake(3600)).is_none());
        assert!(checks.running.is_some());
    }

    #[test]
    fn a_sleep_while_a_check_runs_does_not_stop_it_however_far_the_calendar_moved() {
        let mut checks = Checks::new(command("exec /bin/sleep 60"));
        let start = Instant::now();
        checks.tick(10, start);
        let pid = checks.running.as_ref().unwrap().child.id();
        let awake = start + Duration::from_secs(1799);
        assert!(checks.tick(10 + 86_400, awake).is_none());
        assert_eq!(checks.running.as_ref().unwrap().child.id(), pid);
    }

    #[test]
    fn stopping_the_background_core_stops_its_full_check_and_the_checks_tools() {
        check_tools_stop(false);
    }

    #[test]
    fn an_unexpected_check_exit_leaves_no_tools_running() {
        check_tools_stop(true);
    }

    fn check_tools_stop(kill_child: bool) {
        let dir = std::env::temp_dir().join(format!(
            "immunity-check-stop-{}-{kill_child}",
            std::process::id()
        ));
        let _removed = crate::common::Scratch::at(dir.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let pid_file = dir.join("child");
        let mut cmd = command("/bin/sleep 60 & echo $! > \"$1\"; wait");
        cmd.arg("check").arg(&pid_file);
        let mut checks = Checks::new(cmd);
        checks.tick(10, Instant::now());
        let pid = checks.running.as_ref().unwrap().child.id() as libc::pid_t;
        let end = Instant::now() + Duration::from_secs(10);
        let tool: libc::pid_t = loop {
            if let Ok(contents) = std::fs::read_to_string(&pid_file)
                && let Ok(pid) = contents.trim().parse()
            {
                break pid;
            }
            assert!(Instant::now() < end, "the invented tool did not start");
            std::thread::sleep(Duration::from_millis(10));
        };
        if kill_child {
            checks.running.as_mut().unwrap().child.kill().unwrap();
            assert!(finished(&mut checks, 10).is_err());
        } else {
            drop(checks);
        }
        // SAFETY: signal 0 only asks whether these invented processes still exist.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        while unsafe { libc::kill(tool, 0) } == 0 {
            assert!(Instant::now() < end, "the check left its tool running");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn moving_the_clock_back_does_not_put_off_full_checks_until_the_old_time() {
        let mut checks = Checks::new(command("exit 0"));
        finished(&mut checks, 10000).unwrap();
        assert!(checks.tick(10, Instant::now()).is_none());
        assert!(checks.running.is_some());
        finished(&mut checks, 10).unwrap();
        assert!(checks.tick(11, Instant::now()).is_none());
        assert!(checks.running.is_none());
    }
}
