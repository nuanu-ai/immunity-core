//! Promises of the scripts that build and check the program on a colleague's Mac: what they
//! ask of the Mac is said once and asked by both, and the build finds the binary where cargo
//! put it. Builds run only in temporary trees against invented tools.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// A folder of invented tools, removed when the test ends.
struct Tools(PathBuf);

impl Tools {
    fn new(tag: &str) -> Tools {
        let dir =
            std::env::temp_dir().join(format!("immunity-scripts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        Tools(dir.canonicalize().unwrap())
    }

    fn tool(&self, rel: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = self.0.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A Mac with this macOS and this cargo.
    fn mac(&self, macos: &str, cargo: &str) {
        self.tool(
            "bin/uname",
            "case \"$1\" in -s) echo Darwin ;; -m) echo arm64 ;; esac",
        );
        self.tool("bin/sw_vers", &format!("echo {macos}"));
        self.tool("bin/cargo", &format!("echo 'cargo {cargo} (2025-01-01)'"));
    }

    fn checkout(&self) {
        for rel in [
            "build",
            "check",
            "scripts/prerequisites.sh",
            "scripts/rust-path.sh",
            "scripts/cargo-built.sh",
            // scripts/lint.sh and what it reads.
            "scripts/lint.sh",
            "scripts/probe.sh",
            "scripts/event-level/install",
            "Cargo.toml",
            ".github/workflows/check.yml",
        ] {
            let destination = self.0.join(rel);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::copy(Path::new(ROOT).join(rel), destination).unwrap();
        }
    }

    fn run(&self, script: &str, args: &[&str]) -> std::process::Output {
        Command::new("/bin/sh")
            .arg(self.0.join(script))
            .args(args)
            .current_dir(&self.0)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.0.join("bin").display()),
            )
            .env("RUST_PLACES", "")
            .output()
            .unwrap()
    }

    /// The prerequisites as `./check` and `./build` source them: the exit code and stderr.
    fn prerequisites(&self, part: &str) -> (Option<i32>, String) {
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                ". ./scripts/prerequisites.sh; {part}_prerequisites"
            ))
            .current_dir(ROOT)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.0.join("bin").display()),
            )
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

impl Drop for Tools {
    fn drop(&mut self) {
        common::remove(&self.0);
    }
}

#[test]
fn the_checks_refuse_an_old_macos_and_say_which_is_needed() {
    // macOS 14 has no /usr/bin/jq, which the collector and tests need.
    let t = Tools::new("prerequisites");
    t.mac("14.6.1", "1.89.0");
    let (code, said) = t.prerequisites("rust");
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains(
            "only on Apple Silicon Macs with macOS 15 or later; this Mac has macOS 14.6.1"
        ),
        "{said}"
    );

    t.mac("15.6", "1.89.0");
    assert_eq!(t.prerequisites("rust"), (Some(0), String::new()));
    t.mac("26.1", "1.91.1");
    assert_eq!(t.prerequisites("rust"), (Some(0), String::new()));
}

/// What `cargo build --release --message-format=json-render-diagnostics` prints for this
/// package, one message a line, in the shape the cargo of rust-toolchain.toml prints: a
/// dependency, a build script compiled and run, the contract's library, the binary, the end.
/// Before the binary, the message cargo prints for it when it is only checked and not built,
/// with no executable. Paths are invented. `TARGET` stands for the target folder, which a cargo configuration or
/// CARGO_TARGET_DIR may put anywhere.
const CARGO_BUILD: &str = r#"{"reason":"compiler-artifact","package_id":"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.229","manifest_path":"/example/registry/serde-1.0.229/Cargo.toml","target":{"kind":["lib"],"crate_types":["lib"],"name":"serde","src_path":"/example/registry/serde-1.0.229/src/lib.rs","edition":"2021","doc":true,"doctest":true,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":["default","std"],"filenames":["TARGET/release/deps/libserde-0a1b2c3d4e5f6a7b.rlib","TARGET/release/deps/libserde-0a1b2c3d4e5f6a7b.rmeta"],"executable":null,"fresh":false}
{"reason":"compiler-artifact","package_id":"registry+https://github.com/rust-lang/crates.io-index#libsqlite3-sys@0.39.1","manifest_path":"/example/registry/libsqlite3-sys-0.39.1/Cargo.toml","target":{"kind":["custom-build"],"crate_types":["bin"],"name":"build-script-build","src_path":"/example/registry/libsqlite3-sys-0.39.1/build.rs","edition":"2021","doc":false,"doctest":false,"test":false},"profile":{"opt_level":"0","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":["bundled"],"filenames":["TARGET/release/build/libsqlite3-sys-1b2c3d4e5f6a7b8c/build-script-build"],"executable":null,"fresh":false}
{"reason":"build-script-executed","package_id":"registry+https://github.com/rust-lang/crates.io-index#libsqlite3-sys@0.39.1","linked_libs":["static=sqlite3"],"linked_paths":["native=TARGET/release/build/libsqlite3-sys-2c3d4e5f6a7b8c9d/out"],"cfgs":[],"env":[],"out_dir":"TARGET/release/build/libsqlite3-sys-2c3d4e5f6a7b8c9d/out"}
{"reason":"compiler-artifact","package_id":"path+file:///example/immunity-core/contract#immunity-contract@1.26.0","manifest_path":"/example/immunity-core/contract/Cargo.toml","target":{"kind":["lib"],"crate_types":["lib"],"name":"immunity_contract","src_path":"/example/immunity-core/contract/src/lib.rs","edition":"2024","doc":true,"doctest":true,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["TARGET/release/deps/libimmunity_contract-3d4e5f6a7b8c9d0e.rlib","TARGET/release/deps/libimmunity_contract-3d4e5f6a7b8c9d0e.rmeta"],"executable":null,"fresh":false}
{"reason":"compiler-artifact","package_id":"path+file:///example/immunity-core#immunity-core@0.1.0","manifest_path":"/example/immunity-core/Cargo.toml","target":{"kind":["bin"],"crate_types":["bin"],"name":"immunity","src_path":"/example/immunity-core/src/main.rs","edition":"2024","doc":true,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["TARGET/release/deps/libimmunity-4e5f6a7b8c9d0e1f.rmeta"],"executable":null,"fresh":false}
{"reason":"compiler-artifact","package_id":"path+file:///example/immunity-core#immunity-core@0.1.0","manifest_path":"/example/immunity-core/Cargo.toml","target":{"kind":["bin"],"crate_types":["bin"],"name":"immunity","src_path":"/example/immunity-core/src/main.rs","edition":"2024","doc":true,"doctest":false,"test":true},"profile":{"opt_level":"3","debuginfo":0,"debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["TARGET/release/immunity"],"executable":"TARGET/release/immunity","fresh":false}
{"reason":"build-finished","success":true}
"#;

#[test]
fn the_core_build_and_checks_use_cargos_external_artifact() {
    let t = Tools::new("core-only");
    t.mac("15.6", "1.89.0");
    t.checkout();
    // The build takes the binary from where cargo says it built it, here a target folder that is
    // not target/, read from a recorded stream of cargo's messages, not from a second build.
    let target = t.0.join("elsewhere/cargo target");
    t.tool("elsewhere/cargo target/release/immunity", "exit 99");
    let core = target.join("release/immunity");
    let stream = CARGO_BUILD.replace("TARGET", target.to_str().unwrap());
    std::fs::write(t.0.join("cargo-build.jsonl"), stream).unwrap();
    // Cargo prints its messages only when the build asks for them.
    t.tool("bin/cargo", &format!(
        "case \"$1\" in --version) echo 'cargo 1.89.0' ;; \
         build) case \" $* \" in *' --message-format=json-render-diagnostics '*) cat '{}' ;; esac ;; \
         fmt|clippy|test) exit 0 ;; *) exit 1 ;; esac",
        t.0.join("cargo-build.jsonl").display(),
    ));
    let out = t.run("build", &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        core.to_str().unwrap()
    );
    let out = t.run("check", &["lint", "tests"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    t.tool("bin/cargo", "echo 'cargo 1.88.0'");
    assert_eq!(t.run("build", &[]).status.code(), Some(2));
    assert_eq!(t.run("check", &["lint"]).status.code(), Some(2));
    assert_eq!(t.run("check", &["tests"]).status.code(), Some(2));
    t.tool(
        "bin/cargo",
        "case \"$1\" in --version) echo 'cargo 1.89.0' ;; esac",
    );
    assert_eq!(t.run("build", &[]).status.code(), Some(2));
}

#[test]
fn the_two_halves_of_the_tests_hold_every_test_binary_exactly_once() {
    // The check on GitHub runs `./check tests 1/2` and `./check tests 2/2` side by side in
    // place of `cargo test`: a binary in neither half would never run there.
    let half = |share: &str| {
        let out = Command::new(Path::new(ROOT).join("scripts/test-half.sh"))
            .arg(share)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let mut seen: Vec<String> = format!("{}{}", half("1/2"), half("2/2"))
        .lines()
        .map(str::to_string)
        .collect();
    seen.sort();

    let mut expected: Vec<String> = std::fs::read_dir(Path::new(ROOT).join("tests"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| format!("--test {}", path.file_stem().unwrap().to_str().unwrap()))
        .chain(["--bins".to_string()])
        .collect();
    expected.sort();
    assert_eq!(seen, expected);
    // A library target's tests are in neither half: scripts/lint.sh refuses one.
}
