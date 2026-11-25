use super::*;
use std::process::{Command, Stdio};

fn strings(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn kind(k: &str) -> &'static Interpreter {
    INTERPRETERS.iter().find(|i| i.kind == k).unwrap()
}

#[test]
fn an_interpreter_is_known_by_its_file_name_whatever_its_version() {
    for (name, k) in [
        ("node", "node"),
        ("bun", "node"),
        ("python3.12", "python"),
        ("Python", "python"),
        ("perl5.34", "perl"),
        ("zsh", "shell"),
        ("osascript", "osascript"),
    ] {
        assert_eq!(interpreter(name).map(|i| i.kind), Some(k), "{name}");
    }
    for name in ["nodemon", "git", "pythonw-helper", ""] {
        assert!(interpreter(name).is_none(), "{name}");
    }
}

#[test]
fn code_on_the_command_line_is_judged_by_the_interpreters_own_options() {
    let given = [
        ("node", &["node", "-e", "x"][..]),
        ("node", &["node", "--eval=x"]),
        ("node", &["node", "--inspect", "-p", "x"]),
        ("node", &["node", "-r", "mod", "-e", "x"]),
        ("node", &["node", "--require", "mod", "--eval", "x"]),
        ("shell", &["bash", "-lc", "x"]),
        ("shell", &["sh", "-o", "pipefail", "-c", "x"]),
        ("python", &["python3", "-W", "ignore", "-c", "x"]),
        ("python", &["python3", "-Ic", "x"]),
        ("deno", &["deno", "eval", "x"]),
        ("osascript", &["osascript", "-l", "JavaScript", "-e", "x"]),
        ("perl", &["perl", "-le", "x"]),
        ("perl", &["perl", "-Mstrict", "-e", "x"]),
    ];
    for (k, args) in given {
        assert!(inline_code(kind(k), &strings(args)), "{args:?}");
    }
    let not_given = [
        ("node", &["node", "server.js", "-e"][..]),
        ("node", &["node", "--require=mod", "server.js", "-e", "x"]),
        ("node", &["node", "-r", "-e"]),
        ("shell", &["bash", "script.sh", "-c", "x"]),
        ("shell", &["sh", "-o", "c", "x"]),
        ("shell", &["sh", "--", "-c"]),
        ("shell", &["sh", "-"]),
        ("python", &["python3", "-X", "c", "x.py"]),
        ("python", &["python3", "-m", "http.server", "-c"]),
        ("deno", &["deno", "run", "eval"]),
        ("perl", &["perl", "-Mfeature", "x.pl"]),
        ("node", &["node"]),
    ];
    for (k, args) in not_given {
        assert!(!inline_code(kind(k), &strings(args)), "{args:?}");
    }
}

#[test]
fn a_detached_process_is_one_whose_parent_is_launchd_or_gone_and_only_its_command_line_is_kept_cut()
{
    let seen = |pid, parent, args: &[&str]| Seen {
        pid,
        start: 1,
        parent,
        executable: Some(format!("/x/{}", args[0])),
        name: String::new(),
        terminal: false,
        args: Some(strings(args)),
        around: Around::default(),
    };
    let mut gone_file = seen(13, 1, &["node", "-e", "x"]);
    gone_file.executable = None;
    gone_file.name = "node".into();
    let mut unreadable = seen(14, 10, &["node"]);
    unreadable.args = None;
    let s = derive(
        Reading {
            at: 0,
            processes: vec![
                seen(10, 1, &["node", "-e", "x", "--password", "Fake-Pa55word"]),
                seen(11, 10, &["sh", "-c", "x"]),
                seen(12, 99, &["sh", "-c", "x"]),
                gone_file,
                unreadable,
                seen(15, 10, &["git", "-c", "x"]),
            ],
            connections: Vec::new(),
            other_users: vec![1],
            unreadable: 0,
            ended: 0,
            sockets_unreadable: 0,
            arguments_layout_unknown: false,
        },
        &HashSet::new(),
    );
    let got: Vec<_> = s
        .processes
        .iter()
        .map(|p| (p.pid, p.detached, p.interpreter.map(|i| i.kind), p.shape))
        .collect();
    assert_eq!(
        got,
        [
            (10, true, Some("node"), Some(INLINE_CODE)),
            (11, false, Some("shell"), Some(INLINE_CODE)),
            (12, true, Some("shell"), Some(INLINE_CODE)),
            (13, true, Some("node"), Some(INLINE_CODE)),
            (14, false, Some("node"), None),
            (15, false, None, None),
        ]
    );
    assert_eq!(s.args_unreadable, 1);
    // The rule decides from the shape alone; what is kept is the command line of each
    // process it may fire on, cut, and no other.
    let kept: Vec<_> = s
        .processes
        .iter()
        .map(|p| (p.pid, p.args.clone()))
        .collect();
    let cut = crate::secrets::mark(crate::secrets::FLAG_VALUE, 13);
    assert_eq!(
        kept,
        [
            (10, Some(strings(&["node", "-e", "x", "--password", &cut]))),
            (11, None),
            (12, Some(strings(&["sh", "-c", "x"]))),
            (13, Some(strings(&["node", "-e", "x"]))),
            (14, None),
            (15, None),
        ]
    );
    // A command line longer than the cut reads is kept as marks alone, so what is kept is
    // bounded by it.
    let long = "x".repeat(crate::secrets::LINE_CAP);
    let s = derive(
        Reading {
            at: 0,
            processes: vec![seen(10, 1, &["sh", "-c", &long])],
            connections: Vec::new(),
            other_users: vec![1],
            unreadable: 0,
            ended: 0,
            sockets_unreadable: 0,
            arguments_layout_unknown: false,
        },
        &HashSet::new(),
    );
    let too_long = |n| crate::secrets::mark(crate::secrets::TOO_LONG, n);
    assert_eq!(
        s.processes[0].args,
        Some(vec![
            too_long(2),
            too_long(2),
            too_long(crate::secrets::LINE_CAP)
        ])
    );
}

#[test]
fn a_process_connected_to_a_listed_address_keeps_its_command_line_cut_and_a_parent_it_read() {
    let seen = |pid, parent, args: Option<&[&str]>| Seen {
        pid,
        start: 1,
        parent,
        executable: Some(format!("/x/{pid}")),
        name: String::new(),
        terminal: false,
        args: args.map(strings),
        around: Around::default(),
    };
    let mut no_file = seen(10, 1, None);
    no_file.executable = None;
    let s = derive(
        Reading {
            at: 0,
            processes: vec![
                seen(9, 1, None),
                no_file,
                seen(11, 9, Some(&["sh", "--password", "Fake-Pa55word"])),
                seen(12, 99, Some(&["sh", "x"])),
                seen(13, 10, None),
                seen(14, 9, Some(&["sh", "y"])),
            ],
            connections: Vec::new(),
            other_users: vec![1],
            unreadable: 0,
            ended: 0,
            sockets_unreadable: 0,
            arguments_layout_unknown: false,
        },
        &HashSet::from([(11, 1), (12, 1), (13, 1)]),
    );
    let kept: Vec<_> = s
        .processes
        .iter()
        .map(|p| (p.pid, p.args.clone(), p.parent.as_ref().map(|l| l.pid)))
        .collect();
    let cut = crate::secrets::mark(crate::secrets::FLAG_VALUE, 13);
    // A parent that is gone, or whose file nothing names, and arguments not read are absent;
    // a process not listed keeps neither.
    assert_eq!(
        kept,
        [
            (9, None, None),
            (10, None, None),
            (11, Some(strings(&["sh", "--password", &cut])), Some(9)),
            (12, Some(strings(&["sh", "x"])), None),
            (13, None, None),
            (14, None, None),
        ]
    );
    assert_eq!(s.processes[2].parent.as_ref().unwrap().executable, "/x/9");
}

#[test]
fn connections_to_a_listed_address_are_found_in_either_form_and_others_are_not() {
    let c = |a: &str, port| Connection {
        pid: 1,
        start: 1,
        transport: "tcp",
        state: "established",
        address: a.parse::<IpAddr>().unwrap().to_canonical(),
        port,
    };
    let all = [
        c("192.0.2.7", 80),
        c("::ffff:192.0.2.8", 443),
        c("2001:db8::1", 443),
        c("198.51.100.1", 80),
    ];
    let list: Vec<IpAddr> = ["::ffff:192.0.2.7", "192.0.2.8", "2001:db8::1"]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
    let found: Vec<_> = connections_to(&all, &list);
    assert_eq!(found, vec![&all[0], &all[1], &all[2]]);
    assert!(connections_to(&all, &[]).is_empty());
}

#[test]
fn a_signer_is_looked_up_once_per_file_and_again_when_the_file_is_replaced() {
    let dir = std::env::temp_dir().join(format!("immunity-signers-{}", std::process::id()));
    let _removed = crate::common::Scratch::at(dir.clone());
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("tool");
    std::fs::write(&file, "one").unwrap();
    let path = file.to_str().unwrap();
    let mut s = Signers::default();
    s.of(path);
    s.of(path);
    assert_eq!(s.looked_up, 1);
    std::fs::remove_file(&file).unwrap();
    std::fs::write(&file, "two!").unwrap();
    s.of(path);
    assert_eq!(s.looked_up, 2);
    assert_eq!(
        s.of("/bin/sh").as_deref().map(|v| v.starts_with("apple")),
        Some(true)
    );
    assert_eq!(s.of(dir.join("absent").to_str().unwrap()), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The real reading, on this test process and a child it starts.
///
/// The tests here start their children by `posix_spawn`, never by `fork`: in a test binary
/// whose other threads are busy, a forked child can die in libSystem's fork handlers
/// before it execs, and `spawn` still returns its pid.
#[test]
fn the_reading_of_the_system_sees_this_process_its_child_with_code_and_its_connection() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.connect(("127.0.0.1", port)).unwrap();
    let six = std::net::TcpListener::bind("[::1]:0").unwrap();
    let six_port = six.local_addr().unwrap().port();
    let six_stream = std::net::TcpStream::connect(("::1", six_port)).unwrap();
    let mut child = Command::new("/bin/sh")
        .args(["-c", "sleep 30; :"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let given = strings(&["/bin/sh", "-c", "sleep 30; :"]);
    let r = reading_where(child.id(), &given, || {
        format!("; the child: {:?}", child.try_wait())
    });
    // What the argument area held is zeroed once it is read. Read of this process, whose
    // arguments stay put: the child's cannot be read while the stub starts the shell, which
    // may come after the reading above.
    let mut area = vec![0u8; argmax()];
    assert_eq!(
        arguments(std::process::id() as i32, &mut area).map(|a| a.1),
        Some(std::env::args().collect())
    );
    assert!(area.iter().all(|&b| b == 0));
    let me = std::process::id() as i32;
    let this = r.processes.iter().find(|p| p.pid == me).unwrap();
    let exe = std::env::current_exe().unwrap();
    assert_eq!(this.executable.as_deref(), exe.to_str());
    let started = this.start / 1_000_000;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(started <= now && now - started < 3600, "{started}");
    let kid = r
        .processes
        .iter()
        .find(|p| p.pid == child.id() as i32)
        .unwrap();
    assert_eq!(kid.parent, me);
    // A controlling terminal is the one `/dev/tty` opens, and the child shares this one's.
    let terminal = std::fs::File::open("/dev/tty").is_ok();
    assert_eq!((this.terminal, kid.terminal), (terminal, terminal));
    let to_listener = r
        .connections
        .iter()
        .find(|c| c.pid == me && c.port == port && c.transport == "tcp")
        .unwrap();
    assert_eq!(to_listener.start, this.start);
    assert_eq!(to_listener.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        (to_listener.transport, to_listener.state),
        ("tcp", "established")
    );
    let mine = |port| r.connections.iter().find(|c| c.pid == me && c.port == port);
    let datagram = r
        .connections
        .iter()
        .find(|c| c.pid == me && c.transport == "udp" && c.port == port)
        .unwrap();
    assert_eq!(datagram.state, "connected");
    assert_eq!(
        mine(six_port).map(|c| c.address),
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
    );
    assert!(r.other_users.contains(&1));
    // The child as one connected to a listed address: it keeps its parent, this process.
    let listed = HashSet::from([(kid.pid, kid.start)]);
    let s = derive(r, &listed);
    let kid = s
        .processes
        .iter()
        .find(|p| p.pid == child.id() as i32)
        .unwrap();
    assert_eq!(kid.shape, Some(INLINE_CODE));
    assert!(!kid.detached);
    let parent = Leader {
        pid: me,
        executable: exe.to_str().unwrap().to_string(),
    };
    assert_eq!(kid.parent, Some(parent));
    child.kill().unwrap();
    child.wait().unwrap();
    drop((stream, udp, six_stream));
}

/// An interpreter whose file was deleted while it runs is still known, by the absolute path
/// it was started by. A copy of a system shell cannot stand in for one on a real system:
/// macOS stops a copied platform binary before it runs.
#[test]
fn an_interpreter_whose_file_is_gone_is_known_by_the_path_it_was_started_by() {
    let s = |p: &str| p.to_string();
    assert_eq!(
        where_from(Some(s("/opt/a/node")), s("/opt/b/node")),
        Some(s("/opt/a/node"))
    );
    assert_eq!(where_from(None, s("/opt/b/node")), Some(s("/opt/b/node")));
    assert_eq!(where_from(None, s("node")), None);
}

/// A shell that its parent left behind is detached: its parent is launchd now.
#[test]
fn the_reading_of_the_system_sees_a_process_its_parent_left_as_detached() {
    let out = Command::new("/bin/sh")
        .args([
            "-c",
            "/bin/sh -c 'sleep 30; :' </dev/null >/dev/null 2>&1 & echo $!",
        ])
        .output()
        .unwrap();
    let pid: i32 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("{e}: {out:?}"));
    let s = derive(
        reading_where(
            pid as u32,
            &strings(&["/bin/sh", "-c", "sleep 30; :"]),
            String::new,
        ),
        &HashSet::new(),
    );
    // SAFETY: a plain signal to the shell this test started.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let left = s.processes.iter().find(|p| p.pid == pid).unwrap();
    assert!(left.detached);
    assert_eq!(left.shape, Some(INLINE_CODE));
    // `/bin/sh` is a stub that starts the shell it is set to be.
    assert_eq!(left.interpreter.map(|i| i.kind), Some("shell"));
}

/// A shell left behind by its parent still names the folder it runs in and the leader of its
/// process group, a shell this test starts as a group of its own that is still running. The
/// leader itself names no leader: it leads its own group.
#[test]
fn a_process_its_parent_left_names_its_folder_and_its_group_leader_while_that_one_runs() {
    use std::io::BufRead;
    use std::os::unix::process::CommandExt;
    let dir = std::env::temp_dir().join(format!("immunity-around-{}", std::process::id()));
    let _removed = crate::common::Scratch::at(dir.clone());
    std::fs::create_dir_all(&dir).unwrap();
    let left = "/bin/sh -c '/bin/sh -c \"sleep 30; :\" </dev/null >/dev/null 2>&1 & echo $!'";
    let mut leader = Command::new("/bin/sh")
        .args(["-c", &format!("{left}; sleep 30; :")])
        .current_dir(&dir)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(leader.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let pid: i32 = line
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("{e}: {line:?}"));
    let r = reading_where(
        pid as u32,
        &strings(&["/bin/sh", "-c", "sleep 30; :"]),
        String::new,
    );
    // SAFETY: a plain signal to the shell this test started.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    leader.kill().unwrap();
    leader.wait().unwrap();
    let of = |pid: i32| r.processes.iter().find(|p| p.pid == pid).unwrap();
    let around = &of(pid).around;
    let real = std::fs::canonicalize(&dir).unwrap();
    assert_eq!(around.working_directory.as_deref(), real.to_str());
    let group = around.group.as_ref().unwrap();
    assert_eq!(group.pid, leader.id() as i32);
    assert!(group.executable.starts_with('/'), "{group:?}");
    assert_eq!(of(group.pid).around.group, None);
    assert_ne!(around.session.as_ref().map(|l| l.pid), Some(pid));
}

#[test]
fn a_leader_is_named_only_when_it_is_another_process_than_launchd_and_runs() {
    let me = std::process::id() as i32;
    assert_eq!(leader(me, me), None);
    assert_eq!(leader(me, 1), None);
    assert_eq!(leader(me, -1), None);
    // A pid no process has: the kernel's pids stay below 100,000.
    assert_eq!(leader(1, 999_999), None);
    let exe = std::env::current_exe().unwrap();
    assert_eq!(
        leader(1, me),
        Some(Leader {
            pid: me,
            executable: exe.to_str().unwrap().to_string()
        })
    );
}

/// A reading of the system in which the process `pid` has the arguments `args`, read again
/// until it has them, for ten seconds: loose enough for a loaded machine, it only ends a wait
/// that would otherwise not end. `/bin/sh` is a stub that starts the shell it is set to be:
/// the stub's arguments can be read, then not while it starts the shell, then the shell's.
fn reading_where(pid: u32, args: &[String], mut also: impl FnMut() -> String) -> Reading {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let r = read_system(1);
        let seen = r.processes.iter().find(|p| p.pid == pid as i32);
        if seen.and_then(|p| p.args.as_deref()) == Some(args) {
            return r;
        }
        assert!(
            std::time::Instant::now() < until,
            "process {pid} was not read with {args:?} in ten seconds; last seen (executable, arguments): {:?}{}",
            seen.map(|p| (&p.executable, &p.args)),
            also()
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn the_argument_area_is_read_to_its_count_and_the_environment_is_not() {
    // The path with its zero byte is padded to a multiple of eight bytes: "/bin/zsh" by
    // seven, "/bin/sh" by none.
    let area = |argc: i32, rest: &[u8]| [&argc.to_ne_bytes()[..], rest].concat();
    let read = |argc, rest: &[u8]| parse_procargs(&area(argc, rest)).map(|(_, args)| args);
    let zsh = |tail: &[u8]| [&b"/bin/zsh\0\0\0\0\0\0\0\0"[..], tail].concat();
    assert_eq!(
        parse_procargs(&area(2, &zsh(b"sh\0-c\0SECRET=1\0"))),
        Some(("/bin/zsh".to_string(), strings(&["sh", "-c"])))
    );
    // An empty argument is a string of length zero, first, in the middle or last; the
    // arguments after it stay in place and no string of the environment is taken.
    let cases: [(i32, &[u8], &[&str]); 4] = [
        (3, b"sh\0\0x\0SECRET=1\0", &["sh", "", "x"]),
        (3, b"sh\0x\0\0SECRET=1\0", &["sh", "x", ""]),
        (2, b"\0x\0SECRET=1\0", &["", "x"]),
        (1, b"\0SECRET=1\0", &[""]),
    ];
    for (argc, tail, want) in cases {
        assert_eq!(read(argc, &zsh(tail)), Some(strings(want)), "{tail:?}");
    }
    assert_eq!(
        read(2, b"/bin/sh\0\0x\0SECRET=1\0"),
        Some(strings(&["", "x"]))
    );
    // A count larger than the strings there reads nothing.
    assert_eq!(read(4, &zsh(b"sh\0-c\0SECRET=1\0")), None);
    assert_eq!(parse_procargs(&[2, 0]), None);
}

#[test]
fn only_zero_bytes_are_skipped_after_the_path_so_no_argument_loses_its_first_bytes() {
    let area = |argc: i32, rest: &[u8]| [&argc.to_ne_bytes()[..], rest].concat();
    // Padded by three, short of eight: the first argument is read whole.
    assert_eq!(
        parse_procargs(&area(2, b"/bin/zsh\0\0\0\0sh\0-c\0SECRET=1\0")),
        Some(("/bin/zsh".to_string(), strings(&["sh", "-c"])))
    );
    // No arguments and nothing after the path: none, as the count says.
    assert_eq!(
        parse_procargs(&area(0, b"/bin/zsh\0")),
        Some(("/bin/zsh".to_string(), Vec::new()))
    );
}

#[test]
fn the_layout_is_known_only_when_the_readers_own_arguments_read_as_it_was_started_with() {
    let own = || {
        ["immunity", "", "sample"]
            .map(std::ffi::OsString::from)
            .into_iter()
    };
    let read = |a: &[&str]| Some(("/x/immunity".to_string(), strings(a)));
    assert!(layout_known(read(&["immunity", "", "sample"]), own()));
    // Shifted by one, an extra empty first argument, or not read at all.
    assert!(!layout_known(read(&["", "sample", "SECRET=1"]), own()));
    assert!(!layout_known(read(&["", "immunity", ""]), own()));
    assert!(!layout_known(None, own()));
}

/// The layout of an empty first argument on this kernel, read from a child this test
/// starts with invented arguments and environment.
#[test]
fn an_empty_first_argument_of_a_running_process_is_read_as_it_is() {
    use std::os::unix::process::CommandExt;
    let mut child = Command::new("/bin/sleep")
        .arg0("")
        .arg("30")
        .env_clear()
        .env("SECRET", "1")
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let mut area = vec![0u8; argmax()];
    let read = arguments(child.id() as i32, &mut area);
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(read, Some(("/bin/sleep".to_string(), strings(&["", "30"]))));
}
