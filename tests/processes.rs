//! Promises of `immunity sample` and its rule. Each test feeds the real binary readings made of
//! invented processes, through the same path a reading of the system takes once it is read;
//! the reading of the system itself is tested in `src/processes.rs` on the test process and a
//! child it starts. No test reads the real processes of this Mac.

mod common;

use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "immunity-proc-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Dir(path)
    }

    fn store(&self) -> PathBuf {
        self.0.join("store.db")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        common::remove(&self.0);
    }
}

fn immunity(dir: &Dir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_immunity"))
        .env("HOME", &dir.0)
        .current_dir(&dir.0)
        .args(args)
        .arg("--store")
        .arg(dir.store())
        .output()
        .unwrap()
}

/// Feeds one reading at time `at` and returns what `immunity sample --json` answered.
fn sample(dir: &Dir, at: i64, processes: &[Value]) -> Value {
    let connection = json!({ "pid": 4242, "start": 7, "transport": "tcp",
                              "address": "::ffff:192.0.2.9", "port": 80 });
    sample_with(dir, at, processes, &[connection])
}

/// Feeds one reading with these connections.
fn sample_with(dir: &Dir, at: i64, processes: &[Value], connections: &[Value]) -> Value {
    let input = dir.0.join(format!("reading-{at}.json"));
    let reading = json!({ "at": at, "processes": processes, "connections": connections,
                          "other_users": [1, 80, 81, 82, 83, 84, 85], "unreadable": 2, "ended": 3,
                          "sockets_unreadable": 1 });
    std::fs::write(&input, reading.to_string()).unwrap();
    let out = immunity(
        dir,
        &[
            "sample",
            "--json",
            "--sample-input",
            input.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    v.clone()
}

/// `immunity <args> --json`, which must answer.
fn contract(dir: &Dir, args: &[&str]) -> Value {
    let mut args = args.to_vec();
    args.push("--json");
    let out = immunity(dir, &args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Every finding, in every state, each read whole with `immunity finding <id> --json`.
fn findings(dir: &Dir) -> Vec<Value> {
    contract(dir, &["findings"])["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| contract(dir, &["finding", f["finding"]["id"].as_str().unwrap()]))
        .collect()
}

/// The pid and start of the process a finding of the rule names.
fn identity(f: &Value) -> (i64, i64) {
    let p = &f["evidence"]["detached_process"];
    (
        p["pid"].as_i64().unwrap(),
        p["start_micros"].as_i64().unwrap(),
    )
}

/// A process as a reading gives it.
fn process(pid: i64, start: i64, parent: i64, exe: &str, args: &[&str], terminal: bool) -> Value {
    json!({ "pid": pid, "start": start, "parent": parent, "executable": exe,
            "name": exe.rsplit('/').next(), "terminal": terminal, "args": args })
}

const T: i64 = 1_800_000_000;
/// Something a command line holds: it stands for the code a process was given.
const MARKER: &str = "inline-code-TOKEN-5f1c";

/// The one that must fire, a node given code with its parent gone, and those that must not.
fn table(at: i64) -> Vec<Value> {
    let code = format!("require('net').connect(80, '{MARKER}')");
    vec![
        // The parent of the others, alive.
        process(
            500,
            1,
            1,
            "/Applications/Tool.app/Contents/MacOS/Tool",
            &["Tool"],
            false,
        ),
        // Must fire: detached, code on its command line, no terminal.
        process(
            4242,
            7,
            1,
            "/opt/tools/bin/node",
            &["node", "-e", &code],
            false,
        ),
        // Must not: a terminal was its own when it was first seen.
        process(
            4300,
            7,
            1,
            "/opt/other/bin/node",
            &["node", "-e", &code],
            at == T,
        ),
        // Must not: its parent is alive and is not launchd.
        process(4301, 7, 500, "/bin/sh", &["sh", "-c", &code], false),
        // Must not: it runs a script, and what follows the script is the script's.
        process(
            4302,
            7,
            1,
            "/opt/tools/bin/node",
            &["node", "server.js", "-e", &code],
            false,
        ),
        // Must not: not an interpreter.
        process(4303, 7, 1, "/usr/bin/git", &["git", "-c", &code], false),
        // Must not: the same pid started again is another process, seen once.
        process(4304, at, 1, "/bin/zsh", &["zsh", "-c", &code], false),
    ]
}

#[test]
fn a_detached_interpreter_given_code_is_a_finding_once_two_samples_a_minute_apart_saw_it() {
    let dir = Dir::new("fires");
    // A first sample can fire nothing: it only starts tracking.
    let first = sample(&dir, T, &table(T));
    assert_eq!(first["findings_opened"], 0);
    assert_eq!(first["tracked_new"], 3);
    assert_eq!(first["interpreters"]["inline_code"], 4);
    assert_eq!(first["interpreters"]["inline_code_detached"], 3);
    // Two samples, but under a minute apart.
    assert_eq!(sample(&dir, T + 59, &table(T + 59))["findings_opened"], 0);
    assert!(findings(&dir).is_empty());

    let third = sample(&dir, T + 60, &table(T + 60));
    assert_eq!(third["findings_opened"], 1);
    let items = findings(&dir);
    assert_eq!(items.len(), 1, "{items:?}");
    let f = &items[0];
    assert_eq!(f["finding"]["rule"], "processes.detached-inline-code");
    assert_eq!(f["technique_text"], "T1059");
    assert_eq!(
        (&f["finding"]["severity"], &f["finding"]["confidence"]),
        (&json!("high"), &json!("medium"))
    );
    assert_eq!(f["finding"]["state"], "open");
    assert_eq!(f["where_text"], "/opt/tools/bin/node");
    // The process by its pid and start, which name it, and the command line it was given.
    let p = &f["evidence"]["detached_process"];
    assert_eq!((&p["pid"], &p["start_micros"]), (&json!(4242), &json!(7)));
    let code = format!("require('net').connect(80, '{MARKER}')");
    assert_eq!(p["args_text"], json!(["node", "-e", code]));

    // It stays one finding while the process lives.
    let fourth = sample(&dir, T + 120, &table(T + 120));
    assert_eq!(fourth["findings_opened"], 0);
    assert_eq!(fourth["tracked_again"], 2);
    assert_eq!(findings(&dir).len(), 1);

    // Who signed what it tracks is kept beside it.
    let conn = rusqlite::Connection::open(dir.store()).unwrap();
    let signer: String = conn
        .query_row(
            "SELECT code_signature FROM tracked_process WHERE executable = '/bin/zsh' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(signer.starts_with("apple"), "{signer}");
}

#[test]
fn an_interpreter_inside_a_folder_macos_asks_permission_for_is_not_looked_at_and_that_is_said() {
    // The watcher samples every 30 seconds. Looking up who signed an executable in Documents
    // would make macOS ask the owner, again and again; the sample names what it left alone.
    let dir = Dir::new("guarded-exe");
    let inside = dir.0.join("Documents/bin/zsh");
    let outside = dir.0.join("tools/zsh");
    for exe in [&inside, &outside] {
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::copy("/bin/zsh", exe).unwrap();
    }
    let code = format!("print {MARKER}");
    let table = [
        process(
            4400,
            7,
            1,
            inside.to_str().unwrap(),
            &["zsh", "-c", &code],
            false,
        ),
        process(
            4401,
            7,
            1,
            outside.to_str().unwrap(),
            &["zsh", "-c", &code],
            false,
        ),
    ];
    // The kernel names an executable by its real path, which may not be the home folder's
    // name as HOME gives it.
    let real = std::fs::canonicalize(&inside).unwrap();
    let mut table = table.to_vec();
    table.push(process(
        4402,
        7,
        1,
        real.to_str().unwrap(),
        &["zsh", "-c", &code],
        false,
    ));
    sample(&dir, T, &table);
    let signed = |exe: &PathBuf| {
        rows(
            &dir,
            &format!(
                "SELECT ifnull(code_signature, 'not checked') FROM tracked_process
                 WHERE executable = '{}'",
                exe.display()
            ),
        )
    };
    assert_eq!(signed(&inside), ["not checked"]);
    assert_eq!(signed(&real), ["not checked"]);
    assert_ne!(signed(&outside), ["not checked"]);
    let guarded = "SELECT completeness || '|' || reason FROM coverage
                   WHERE reader = 'processes' AND kind = 'folders macOS asks permission for'";
    assert_eq!(rows(&dir, guarded), ["none|not looked into: ~/Documents"]);
    // The words say it is programs that were not looked at.
    let out = immunity(&dir, &["status", "--json"]);
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let titles: Vec<&str> = v["not_covered"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["id"] == "protected-folders")
        .map(|u| u["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        titles,
        ["Programs inside a folder macOS protects are not checked."]
    );

    // Said while it runs, and no longer once it is gone.
    sample(&dir, T + 30, &table);
    assert_eq!(rows(&dir, guarded), ["none|not looked into: ~/Documents"]);
    sample(&dir, T + 60, &table[1..2]);
    assert!(rows(&dir, guarded).is_empty());
}

#[test]
fn after_the_owner_has_seen_it_the_same_process_raises_nothing_and_another_one_does() {
    let dir = Dir::new("seen");
    let exe = dir.0.join(".local/bin/python3.12");
    let one = |pid| {
        vec![process(
            pid,
            7,
            1,
            exe.to_str().unwrap(),
            &["python3", "-c", "x"],
            false,
        )]
    };
    sample(&dir, T, &one(10));
    sample(&dir, T + 60, &one(10));
    let found = findings(&dir);
    // A program under the home folder is shown as the other readers show it.
    assert_eq!(found[0]["where_text"], "~/.local/bin/python3.12");
    let id = found[0]["finding"]["id"].as_str().unwrap().to_string();
    assert!(immunity(&dir, &["finding", &id, "seen"]).status.success());

    assert_eq!(sample(&dir, T + 120, &one(10))["findings_opened"], 0);
    assert_eq!(sample(&dir, T + 180, &one(11))["findings_opened"], 0);
    assert_eq!(sample(&dir, T + 240, &one(11))["findings_opened"], 1);
    let open: Vec<_> = findings(&dir)
        .into_iter()
        .filter(|f| f["finding"]["state"] == "open")
        .collect();
    assert_eq!(open.len(), 1);
    // The new finding names the process that raised it, not the one already seen.
    assert_eq!(identity(&open[0]), (11, 7));
}

#[test]
fn a_finding_still_open_names_the_latest_process_of_its_program_a_sample_saw() {
    // A response layer that looks at the process looks at the one running now.
    let dir = Dir::new("latest");
    let exe = dir.0.join(".local/bin/python3.12");
    let one = |pid| {
        vec![process(
            pid,
            7,
            1,
            exe.to_str().unwrap(),
            &["python3", "-c", "x"],
            false,
        )]
    };
    sample(&dir, T, &one(10));
    sample(&dir, T + 60, &one(10));
    sample(&dir, T + 120, &one(11));
    sample(&dir, T + 180, &one(11));
    let found = findings(&dir);
    assert_eq!(found.len(), 1);
    assert_eq!(identity(&found[0]), (11, 7));
    let id = found[0]["finding"]["id"].as_str().unwrap();
    let out = immunity(&dir, &["findings"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("No full check has finished."), "{text}");
    assert!(text.contains(id), "{text}");
    let out = immunity(&dir, &["finding", id]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("\n    Process      pid 11, started 1970-01-01 00:00 UTC\n"),
        "{text}"
    );
}

/// The invented secrets of each kind the cut knows, as the tests of `src/secrets.rs` plant them,
/// given to one shell as arguments: the arguments and the secrets.
fn planted() -> (Vec<&'static str>, [&'static str; 5]) {
    // Split, so that no scanner takes this source for one that holds a token.
    let token = concat!("gh", "p_Fk7Qz2Lm9Xw4Rt8Yp3Vn6Bc1Hd5Js0Ga7Ke2");
    let args = vec![
        "zsh",
        "-c",
        "sleep 60",
        "tool",
        token,
        "--password",
        "Fake-Pa55word",
        "https://someone:FakePassw0rd@example.invalid/r",
        "-H",
        "Authorization: Bearer FAKEexample0opaque1token2",
        "mysql",
        "-u",
        "root",
        "-pFakePassw0rdExample",
    ];
    let secrets = [
        token,
        "Fake-Pa55word",
        "FakePassw0rd",
        "FAKEexample0opaque1token2",
        "FakePassw0rdExample",
    ];
    (args, secrets)
}

/// What `immunity <args>` printed on standard output, which must succeed.
fn printed(dir: &Dir, args: &[&str]) -> Vec<u8> {
    let out = immunity(dir, args);
    assert!(out.status.success(), "{args:?}: {out:?}");
    out.stdout
}

/// Every page `immunity view` writes, one after the other.
fn pages(dir: &Dir) -> String {
    String::from_utf8(printed(dir, &["view", "--no-open"]))
        .unwrap()
        .lines()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect()
}

/// Every file under `folder` but the readings a test fed, which hold what it gave.
fn kept_files(folder: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(folder).unwrap() {
        let path = entry.unwrap().path();
        let name = path.display().to_string();
        if path.is_dir() {
            kept_files(&path, out);
        } else if !name.contains("/reading-") {
            out.push((name, std::fs::read(&path).unwrap()));
        }
    }
}

fn holds(bytes: &[u8], text: &str) -> bool {
    bytes.windows(text.len()).any(|w| w == text.as_bytes())
}

/// The id of the one finding there is.
fn the_finding(dir: &Dir) -> String {
    let all = findings(dir);
    assert_eq!(all.len(), 1, "{all:?}");
    all[0]["finding"]["id"].as_str().unwrap().to_string()
}

#[test]
fn a_secret_on_the_command_line_of_a_detached_process_reaches_no_file_and_no_output() {
    // The command line of the process the rule fires on is kept and printed, every secret in it
    // cut, in the store, the journal, every form of the finding and the pages. That of a process
    // it does not fire on is kept nowhere.
    let dir = Dir::new("secret");
    let (args, secrets) = planted();
    let other = format!("print {MARKER}");
    let table = vec![
        process(500, 1, 1, "/opt/tools/bin/tool", &["tool"], false),
        process(4242, 7, 1, "/bin/zsh", &args, false),
        process(4301, 7, 500, "/bin/sh", &["sh", "-c", &other], false),
    ];
    sample(&dir, T, &table);
    let said = sample(&dir, T + 60, &table);
    assert_eq!(said["findings_opened"], 1);
    let id = the_finding(&dir);
    let json = printed(&dir, &["finding", &id, "--json"]);
    let v: Value = serde_json::from_slice(&json).unwrap();
    let p = &v["evidence"]["detached_process"];
    let kinds: Vec<&str> = p["cuts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        kinds,
        [
            "gitleaks:github-pat",
            "immunity:flag-value",
            "detect-secrets:basic-auth",
            "immunity:authorization",
            "immunity:mysql-password",
        ]
    );
    assert_eq!(p["args_text"][6], r"\cut{immunity:flag-value 13}");
    let text = printed(&dir, &["finding", &id]);
    let page = pages(&dir);
    assert!(holds(&text, r"--password \cut{immunity:flag-value 13}"));
    assert!(holds(page.as_bytes(), r"\cut{immunity:mysql-password 19}"));
    let mut kept = vec![
        ("sample".to_string(), said.to_string().into_bytes()),
        ("json".to_string(), json),
        ("text".to_string(), text),
        (
            "proto".to_string(),
            printed(&dir, &["finding", &id, "--proto"]),
        ),
        (
            "findings".to_string(),
            printed(&dir, &["findings", "--json"]),
        ),
        ("pages".to_string(), page.into_bytes()),
    ];
    kept_files(&dir.0, &mut kept);
    assert!(kept.iter().any(|(name, _)| name.ends_with("store.db")));
    for (name, bytes) in &kept {
        for secret in secrets {
            assert!(!holds(bytes, secret), "{name}: {secret}");
        }
        assert!(!holds(bytes, MARKER), "{name}");
    }
}

#[test]
fn the_finding_of_a_process_that_has_ended_still_says_what_the_sample_that_raised_it_kept() {
    // What a person or an agent needs to tell a tool's command from hidden code is read while
    // the process runs, and the finding keeps it once the process is gone.
    let dir = Dir::new("ended");
    let guarded = dir.0.join("Documents/bin/agent");
    let mut zsh = process(4242, 7, 1, "/bin/zsh", &["zsh", "-c", "sleep 600"], false);
    zsh["working_directory"] = json!("/Users/example/dev/site");
    zsh["group_leader"] = json!({ "pid": 812, "executable": "/bin/zsh" });
    zsh["session_leader"] = json!({ "pid": 400, "executable": guarded.to_str().unwrap() });
    sample(&dir, T, std::slice::from_ref(&zsh));
    sample(&dir, T + 60, std::slice::from_ref(&zsh));
    // A leader inside a folder macOS asks permission for is not looked at, and that is said.
    let not_looked = "SELECT reason FROM coverage
                      WHERE reader = 'processes' AND kind = 'folders macOS asks permission for'";
    assert_eq!(rows(&dir, not_looked), ["not looked into: ~/Documents"]);
    sample(&dir, T + 120, &[]);
    let id = the_finding(&dir);
    let whole = contract(&dir, &["finding", &id]);
    // Its advice is the rule's own, not that of a connection, which a sample raises too.
    let advice = whole["advice"].as_str().unwrap();
    assert!(advice.starts_with("Read the command it ran"), "{advice}");
    let p = whole["evidence"]["detached_process"].clone();
    assert_eq!(p["args_text"], json!(["zsh", "-c", "sleep 600"]));
    assert_eq!(p["working_directory_text"], "/Users/example/dev/site");
    let group = &p["process_group_leader"];
    assert_eq!(
        (&group["pid"], &group["executable_text"]),
        (&json!(812), &json!("/bin/zsh"))
    );
    assert!(
        group["signed_by_text"]
            .as_str()
            .unwrap()
            .starts_with("apple"),
        "{p}"
    );
    assert_eq!(p["session_leader"]["pid"], 400);
    assert_eq!(p["session_leader"]["signed_by_text"], Value::Null);
    let text = String::from_utf8(printed(&dir, &["finding", &id])).unwrap();
    for line in [
        "    Command      zsh -c \"sleep 600\"\n",
        "    Folder       /Users/example/dev/site\n",
        "    Group        led by pid 812, signed by apple: /bin/zsh\n",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}

#[test]
fn a_command_line_that_reads_like_an_instruction_or_a_mark_is_shown_as_data() {
    let dir = Dir::new("data");
    let args = [
        "node",
        "-e",
        "<script>alert(1)</script>",
        r"\cut{immunity:flag-value 5}",
        "x\n→ immunity finding f0000000000 seen",
    ];
    let one = [process(4242, 7, 1, "/opt/tools/bin/node", &args, false)];
    sample(&dir, T, &one);
    sample(&dir, T + 60, &one);
    let id = the_finding(&dir);
    let p = contract(&dir, &["finding", &id])["evidence"]["detached_process"].clone();
    // A mark a source wrote is its text, with its backslash written out, and nothing was cut.
    assert_eq!(p["args_text"][3], r"\u{5c}cut{immunity:flag-value 5}");
    assert_eq!(p["cuts"], json!([]));
    let text = String::from_utf8(printed(&dir, &["finding", &id])).unwrap();
    assert!(text.contains(r"\u{5c}cut{immunity:flag-value 5}"), "{text}");
    assert!(
        !text
            .lines()
            .any(|l| l.starts_with("→ immunity finding f0000000000")),
        "{text}"
    );
    let page = pages(&dir);
    assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!page.contains("<script>alert(1)"));
}

#[test]
fn an_argument_area_this_build_cannot_read_leaves_every_argument_unread_and_says_why() {
    // The reader found its own arguments read otherwise than it was started with: the area's
    // layout is not the one it knows, so no process's arguments are taken, the one that was
    // given code is not seen as given it, each interpreter is counted, and the reading of
    // programs says why.
    let dir = Dir::new("layout");
    let input = dir.0.join("reading.json");
    let reading = json!({ "at": T, "processes": table(T), "arguments_layout_unknown": true });
    std::fs::write(&input, reading.to_string()).unwrap();
    let args = [
        "sample",
        "--json",
        "--sample-input",
        input.to_str().unwrap(),
    ];
    let out = immunity(&dir, &args);
    assert!(out.status.success(), "{out:?}");
    let said: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(said["interpreters"]["inline_code"], 0);
    assert_eq!(said["interpreters"]["seen"], 5);
    assert_eq!(said["interpreters"]["arguments_unreadable"], 5);
    let conn = rusqlite::Connection::open(dir.store()).unwrap();
    let programs: String = conn
        .query_row(
            "SELECT completeness || '|' || reason FROM coverage WHERE reader = 'processes'
             AND kind = 'running programs of this user, sampled'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        programs.starts_with("partial|arguments not read: "),
        "{programs}"
    );
    let status = contract(&dir, &["status"]).to_string();
    assert!(status.contains("so that area's layout is not the one this build knows"));
}

#[test]
fn every_sample_names_its_level_of_access_and_what_it_cannot_see() {
    let dir = Dir::new("coverage");
    let mut processes = table(T);
    // An interpreter whose arguments could not be read.
    processes.push(json!({ "pid": 9, "start": 1, "parent": 1,
                           "executable": "/opt/tools/bin/node", "name": "node" }));
    let said = sample(&dir, T, &processes);
    assert_eq!(said["level"], "samples without administrator rights");
    assert_eq!(said["processes"]["other_users"], 7);
    assert_eq!(said["processes"]["unreadable"], 2);
    assert_eq!(said["processes"]["ended_while_read"], 3);
    assert_eq!(said["processes"]["read"], 8);
    assert_eq!(said["interpreters"]["seen"], 6);
    assert_eq!(said["interpreters"]["arguments_unreadable"], 1);
    assert_eq!(said["connections"]["read"], 1);
    assert_eq!(said["connections"]["unreadable"], 1);
    // What could not be read makes the sample's coverage partial, by kind.
    let conn = rusqlite::Connection::open(dir.store()).unwrap();
    let covered: Vec<String> = conn
        .prepare(
            "SELECT completeness || '|' || reason FROM coverage WHERE reader = 'processes'
             ORDER BY kind",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        covered,
        [
            "partial|sockets that could not be read: 1",
            "partial|programs that could not be read: 2"
        ]
    );
    let cannot: Vec<&str> = said["cannot_see"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for gap in [
        "the arguments and connections of other users' processes",
        "connections opened and closed between two samples",
        "the names behind addresses: no name resolution is seen",
    ] {
        assert!(cannot.contains(&gap), "{gap}");
    }
    let input = dir.0.join(format!("reading-{T}.json"));
    let text = immunity(&dir, &["sample", "--sample-input", input.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("7 of other users not read"), "{text}");
    assert!(
        text.contains("\n  Cannot see     the arguments and connections of other users"),
        "{text}"
    );
}

#[test]
fn a_sample_waits_for_a_run_in_progress_and_then_stops_writing_nothing() {
    let dir = Dir::new("locked");
    let held = std::fs::File::open(&dir.0).unwrap();
    held.lock().unwrap();
    let input = dir.0.join("reading.json");
    let reading = json!({ "at": T, "processes": table(T) });
    std::fs::write(&input, reading.to_string()).unwrap();
    let out = immunity(
        &dir,
        &[
            "sample",
            "--json",
            "--sample-input",
            input.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(4));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["errors"][0]["code"], "run_in_progress");
    assert!(!dir.store().exists());
}

fn rows(dir: &Dir, sql: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(dir.store()).unwrap();
    let mut stmt = conn.prepare(sql).unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn a_process_gone_for_a_day_is_no_longer_kept_and_one_gone_for_less_is() {
    let dir = Dir::new("trim");
    let gone = || {
        vec![process(
            51,
            7,
            1,
            "/opt/tools/bin/node",
            &["node", "-e", "x"],
            false,
        )]
    };
    sample(&dir, T, &gone());
    sample(&dir, T + 3600, &[]);
    assert_eq!(
        rows(&dir, "SELECT executable FROM tracked_process").len(),
        1
    );
    sample(&dir, T + 24 * 3600 + 1, &[]);
    assert!(rows(&dir, "SELECT executable FROM tracked_process").is_empty());
}

/// A full run of `dir` that reads the indicator list next to the store and nothing real.
fn run(dir: &Dir) {
    let absent = dir.0.join("absent");
    std::fs::write(dir.0.join("brew.json"), r#"{"formulae": [], "casks": []}"#).unwrap();
    std::fs::create_dir_all(dir.0.join("home")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_immunity"))
        .env("HOME", &dir.0)
        .current_dir(&dir.0)
        .args(["run", "--machine-name", "mac", "--store"])
        .arg(dir.store())
        .arg("--brew-input")
        .arg(dir.0.join("brew.json"))
        .args(["--tailscale", "absent", "--threats-input", "absent"])
        .args(["--osv-crates-input", "absent", "--osv-npm-input", "absent"])
        .args(["--osv-pypi-input", "absent"])
        .arg("--system-root")
        .arg(&absent)
        .arg("--servers-input")
        .arg(&absent)
        .arg("--checkouts-root")
        .arg(dir.0.join("home"))
        .arg("--sessions-root")
        .arg(&absent)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_finding_of_a_detached_script_shows_its_own_process_when_another_of_its_program_matches_an_indicator()
 {
    // Both processes run the same program, so the journal entries of the sample that raised the
    // finding name the same subject: the finding shows the process that raised it and its
    // command, never the one whose connection matched the list.
    let dir = Dir::new("same-program");
    std::fs::write(
        dir.0.join("indicators.json"),
        r#"[{"kind": "ipv4-addr:value", "value": "203.0.113.47"}]"#,
    )
    .unwrap();
    run(&dir);
    let table = [
        process(500, 1, 1, "/opt/tools/bin/tool", &["tool"], false),
        process(4242, 7, 1, "/bin/zsh", &["zsh", "-c", "sleep 600"], false),
        process(4243, 9, 500, "/bin/zsh", &["zsh"], false),
    ];
    let listed = json!({ "pid": 4243, "start": 9, "transport": "tcp",
                         "address": "203.0.113.47", "port": 80 });
    sample_with(&dir, T, &table, &[]);
    let said = sample_with(&dir, T + 60, &table, &[listed]);
    assert_eq!(said["connections"]["matched_indicators"], 1);
    let detached: Vec<Value> = findings(&dir)
        .into_iter()
        .filter(|f| f["finding"]["rule"] == "processes.detached-inline-code")
        .collect();
    assert_eq!(detached.len(), 1, "{detached:?}");
    assert_eq!(identity(&detached[0]), (4242, 7));
    assert_eq!(
        detached[0]["evidence"]["detached_process"]["args_text"],
        json!(["zsh", "-c", "sleep 600"])
    );
}

#[test]
fn a_connection_to_a_listed_address_is_a_finding_once_and_a_listed_name_is_never_resolved() {
    let dir = Dir::new("indicator");
    // The address of the list, and a name that is written like an address: a name is not
    // matched against connections, whatever it looks like.
    std::fs::write(
        dir.0.join("indicators.json"),
        r#"[{"kind": "ipv4-addr:value", "value": "203.0.113.47"},
            {"kind": "domain-name:value", "value": "198.51.100.8"}]"#,
    )
    .unwrap();
    run(&dir);
    let tool = |pid| process(pid, 7, 500, "/opt/tools/bin/agent", &["agent"], false);
    let to = |pid, address: &str| json!({ "pid": pid, "start": 7, "transport": "tcp", "address": address, "port": 80 });
    let conns = [to(60, "::ffff:203.0.113.47"), to(61, "198.51.100.8")];
    let said = sample_with(&dir, T, &[tool(60), tool(61)], &conns);
    assert_eq!(said["connections"]["matched_indicators"], 1);
    assert_eq!(said["findings_opened"], 1);
    let f = &findings(&dir)[0];
    assert_eq!(f["finding"]["rule"], "indicator.match");
    assert_eq!(f["where_text"], "/opt/tools/bin/agent");
    assert_eq!(
        f["evidence"]["indicator_matched"]["indicators_text"],
        "[ipv4-addr:value = '203.0.113.47']"
    );
    // The connection stays: one finding, and once the owner has seen it, it stays quiet.
    assert_eq!(
        sample_with(&dir, T + 30, &[tool(60)], &conns[..1])["findings_opened"],
        0
    );
    let id = f["finding"]["id"].as_str().unwrap().to_string();
    assert!(immunity(&dir, &["finding", &id, "seen"]).status.success());
    assert_eq!(
        sample_with(&dir, T + 60, &[tool(60)], &conns[..1])["findings_opened"],
        0
    );
    // A connection that drops for a sample and comes back is the same one, not raised again.
    sample_with(&dir, T + 90, &[tool(60)], &[]);
    assert_eq!(
        sample_with(&dir, T + 120, &[tool(60)], &conns[..1])["findings_opened"],
        0
    );
    assert_eq!(
        rows(&dir, "SELECT entry FROM journal WHERE entry = 'sampled'").len(),
        1
    );
    // Gone for a day, it is no longer kept.
    sample_with(&dir, T + 120 + 24 * 3600 + 1, &[], &[]);
    assert!(rows(&dir, "SELECT indicator FROM matched_connection").is_empty());
}

/// A store whose indicator list holds 203.0.113.7, as a full run leaves it.
fn listed(tag: &str) -> Dir {
    let dir = Dir::new(tag);
    std::fs::write(
        dir.0.join("indicators.json"),
        r#"[{"kind": "ipv4-addr:value", "value": "203.0.113.7"}]"#,
    )
    .unwrap();
    run(&dir);
    dir
}

/// A connection of `pid` to the listed address.
fn to_listed(pid: i64) -> Value {
    json!({ "pid": pid, "start": 7, "transport": "tcp", "address": "203.0.113.7", "port": 8443 })
}

/// The lines of a text that begin with `label`.
fn lines_of(text: &str, label: &str) -> usize {
    text.lines().filter(|l| l.starts_with(label)).count()
}

#[test]
fn a_connection_match_keeps_its_port_transport_parent_and_cut_command_line_after_its_program_ended()
{
    // The case a person cannot close: by the time they read the finding every process of the
    // program has ended. What the sample had in hand is kept, the secret cut before it is stored.
    let dir = listed("connection");
    let (_, secrets) = planted();
    let args = ["node", "server.js", "--password", "Fake-Pa55word"];
    let mut node = process(4242, 7, 500, "/usr/local/bin/node", &args, false);
    node["working_directory"] = json!("/Users/example/dev/shop");
    let table = [process(500, 1, 1, "/bin/zsh", &["zsh"], false), node];
    let said = sample_with(&dir, T, &table, &[to_listed(4242)]);
    assert_eq!(said["findings_opened"], 1);
    sample_with(&dir, T + 60, &[], &[]);
    let id = the_finding(&dir);
    let json = printed(&dir, &["finding", &id, "--json"]);
    let v: Value = serde_json::from_slice(&json).unwrap();
    let m = &v["evidence"]["indicator_matched"];
    assert_eq!((&m["port"], &m["transport"]), (&json!(8443), &json!("tcp")));
    let p = &m["process"];
    assert_eq!((&p["pid"], &p["start_micros"]), (&json!(4242), &json!(7)));
    let cut = r"\cut{immunity:flag-value 13}";
    assert_eq!(
        p["args_text"],
        json!(["node", "server.js", "--password", cut])
    );
    assert_eq!(p["working_directory_text"], "/Users/example/dev/shop");
    assert_eq!(
        (&p["parent"]["pid"], &p["parent"]["executable_text"]),
        (&json!(500), &json!("/bin/zsh"))
    );
    let signer = p["parent"]["signed_by_text"].as_str().unwrap();
    assert!(signer.starts_with("apple"), "{signer}");
    assert!(
        v["advice"]
            .as_str()
            .unwrap()
            .contains("on the list you gave"),
        "{v}"
    );
    let text = printed(&dir, &["finding", &id]);
    let shown = String::from_utf8_lossy(&text);
    for line in [
        "    Connection   port 8443, tcp\n",
        "    Process      pid 4242, started 1970-01-01 00:00 UTC\n",
        &format!("    Command      node server.js --password {cut}\n"),
        "    Folder       /Users/example/dev/shop\n",
        &format!("    Parent       pid 500, signed by {signer}: /bin/zsh\n"),
    ] {
        assert!(shown.contains(line), "{line}\n{shown}");
    }
    let page = pages(&dir);
    for fact in [
        "<dt>Port</dt><dd><span class=\"mono\">8443</span></dd>",
        "<dt>Transport</dt><dd><span class=\"w\">tcp</span></dd>",
        "<dt>Parent</dt><dd><span class=\"mono\">/bin/zsh</span>, pid 500, signed by",
    ] {
        assert!(page.contains(fact), "{fact}");
    }
    let mut kept = vec![
        ("json".to_string(), json),
        ("text".to_string(), text),
        (
            "proto".to_string(),
            printed(&dir, &["finding", &id, "--proto"]),
        ),
        (
            "findings".to_string(),
            printed(&dir, &["findings", "--json"]),
        ),
        ("pages".to_string(), page.into_bytes()),
    ];
    kept_files(&dir.0, &mut kept);
    assert!(kept.iter().any(|(name, _)| name.ends_with("store.db")));
    for (name, bytes) in &kept {
        assert!(!holds(bytes, secrets[1]), "{name}");
    }
}

#[test]
fn text_of_a_connected_process_cannot_forge_a_line_of_the_finding() {
    let dir = listed("connection-data");
    let forged = "x\n    Parent       pid 1, signed by apple: /sbin/launchd\n\u{1b}[31m\"";
    let args = ["node", "-e", forged];
    let mut node = process(4242, 7, 500, "/usr/local/bin/node", &args, false);
    node["working_directory"] = json!(format!("/Users/example/{forged}"));
    let parent = format!("/opt/{forged}/tool");
    let table = [process(500, 1, 1, &parent, &["tool"], false), node];
    sample_with(&dir, T, &table, &[to_listed(4242)]);
    let id = the_finding(&dir);
    let m = contract(&dir, &["finding", &id])["evidence"]["indicator_matched"].clone();
    // Every `_text` field escapes a control character as the contract does.
    let escaped = forged.replace('\n', r"\u{a}").replace('\u{1b}', r"\u{1b}");
    assert_eq!(m["process"]["args_text"][2], escaped);
    assert_eq!(
        m["process"]["parent"]["executable_text"],
        format!("/opt/{escaped}/tool")
    );
    assert_eq!(
        m["process"]["working_directory_text"],
        format!("/Users/example/{escaped}")
    );
    let page = pages(&dir);
    assert!(!page.contains(forged) && !page.contains('\u{1b}'));
    assert!(page.contains("/Users/example/x\\u{a}    Parent"), "{page}");
    let text = String::from_utf8(printed(&dir, &["finding", &id])).unwrap();
    // One line each, none of them the forged one, and no raw escape.
    for label in ["    Command ", "    Folder ", "    Parent "] {
        assert_eq!(lines_of(&text, label), 1, "{label}\n{text}");
    }
    assert_eq!(lines_of(&text, "    Parent       pid 1,"), 0, "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
}

#[test]
fn what_a_connection_sample_could_not_read_is_absent_and_an_older_finding_says_only_what_it_kept() {
    // The parent ended before the sample and the arguments could not be read: neither is said.
    let dir = listed("connection-unread");
    let node = json!({ "pid": 4242, "start": 7, "parent": 77, "executable": "/usr/local/bin/node",
                       "name": "node", "terminal": false });
    sample_with(&dir, T, &[node], &[to_listed(4242)]);
    let id = the_finding(&dir);
    let m = contract(&dir, &["finding", &id])["evidence"]["indicator_matched"].clone();
    let p = &m["process"];
    assert_eq!(p["args_text"], json!([]));
    for field in ["parent", "working_directory_text"] {
        assert!(p[field].is_null(), "{field}: {p}");
    }
    let text = String::from_utf8(printed(&dir, &["finding", &id])).unwrap();
    for label in ["    Command ", "    Folder ", "    Parent "] {
        assert_eq!(lines_of(&text, label), 0, "{label}\n{text}");
    }
    // A finding raised by a build before the connection was kept holds the pid and start alone.
    common::rewrite_journal(
        &dir.store(),
        r#"UPDATE journal SET text = '{"pid":4242,"start":7}' WHERE entry = 'sampled'"#,
    );
    let m = contract(&dir, &["finding", &id])["evidence"]["indicator_matched"].clone();
    assert!(m["port"].is_null() && m["transport"].is_null(), "{m}");
    assert_eq!(m["process"]["pid"], 4242);
    let text = String::from_utf8(printed(&dir, &["finding", &id])).unwrap();
    assert_eq!(lines_of(&text, "    Connection "), 0, "{text}");
    assert_eq!(
        lines_of(&text, "    Process      pid 4242, started"),
        1,
        "{text}"
    );
}

#[test]
fn a_finding_of_a_file_and_a_connection_shows_both_indicators_and_the_process_beside_its_address() {
    // One program both matched by its file's hash and connected to a listed address is one
    // finding: it names both indicators, the process the connection's, and its advice holds.
    let dir = Dir::new("connection-and-file");
    let program = dir.0.join(".zshrc");
    std::fs::write(&program, "export INVENTED=1\n").unwrap();
    let out = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .arg(&program)
        .output()
        .unwrap();
    let hash = String::from_utf8(out.stdout).unwrap()[..64].to_string();
    let list = json!([{ "kind": "file:hashes.'SHA-256'", "value": hash },
                      { "kind": "ipv4-addr:value", "value": "203.0.113.7" }]);
    std::fs::write(dir.0.join("indicators.json"), list.to_string()).unwrap();
    run(&dir);
    let exe = program.to_str().unwrap();
    sample_with(
        &dir,
        T,
        &[process(4242, 7, 1, exe, &["x"], false)],
        &[to_listed(4242)],
    );
    let matched: Vec<Value> = findings(&dir)
        .into_iter()
        .filter(|f| f["finding"]["rule"] == "indicator.match")
        .collect();
    assert_eq!(matched.len(), 1, "{matched:?}");
    let m = &matched[0]["evidence"]["indicator_matched"];
    let both = format!("[file:hashes.'SHA-256' = '{hash}'] OR [ipv4-addr:value = '203.0.113.7']");
    assert_eq!(m["indicators_text"], both);
    assert_eq!(
        (&m["process"]["pid"], &m["port"]),
        (&json!(4242), &json!(8443))
    );
    let advice = matched[0]["advice"].as_str().unwrap();
    assert!(
        advice.starts_with("The program named here reached an address"),
        "{advice}"
    );
}

#[test]
fn the_socket_a_connection_finding_shows_does_not_depend_on_the_order_the_sample_read_them_in() {
    // Two programs, each with the same two sockets to the listed address, read in opposite
    // orders: each finding shows the lowest port.
    let dir = listed("connection-order");
    let table = [
        process(60, 7, 1, "/opt/a/agent", &["agent"], false),
        process(61, 7, 1, "/opt/b/agent", &["agent"], false),
    ];
    let to = |pid, transport, port| {
        json!({ "pid": pid, "start": 7, "transport": transport, "address": "203.0.113.7",
                "port": port })
    };
    let sockets = [
        to(60, "udp", 9000),
        to(60, "tcp", 443),
        to(61, "tcp", 443),
        to(61, "udp", 9000),
    ];
    sample_with(&dir, T, &table, &sockets);
    let shown: Vec<(Value, Value)> = findings(&dir)
        .iter()
        .map(|f| {
            let m = &f["evidence"]["indicator_matched"];
            (m["port"].clone(), m["transport"].clone())
        })
        .collect();
    assert_eq!(
        shown,
        [(json!(443), json!("tcp")), (json!(443), json!("tcp"))]
    );
}

#[test]
fn a_port_or_transport_a_reading_does_not_give_is_absent_and_never_made_up() {
    let dir = listed("connection-unknown");
    let socket = json!({ "pid": 4242, "start": 7, "address": "203.0.113.7", "port": 70_000 });
    let node = process(4242, 7, 1, "/usr/local/bin/node", &["node"], false);
    sample_with(&dir, T, &[node], &[socket]);
    let id = the_finding(&dir);
    let m = contract(&dir, &["finding", &id])["evidence"]["indicator_matched"].clone();
    assert!(m["port"].is_null() && m["transport"].is_null(), "{m}");
    let text = String::from_utf8(printed(&dir, &["finding", &id])).unwrap();
    assert_eq!(lines_of(&text, "    Connection "), 0, "{text}");
}
