#!/bin/sh
# Rules of CLAUDE.md that a plain grep over the repository's own files can hold. Run by
# `./check lint`. Each failure names the rule and where it is broken; a file it cannot read
# fails too, so no rule passes because its file went missing.
cd "$(dirname "$0")/.." || exit 2
failed=0
fail() {
  echo "lint: $*" >&2
  failed=1
}
# grep's own status: 0 found, 1 not found, anything else could not read.
absent() {
  why=$1
  shift
  /usr/bin/grep -H "$@"
  case $? in
    0) fail "$why" ;;
    1) ;;
    *) fail "could not read what this rule is checked on: $why" ;;
  esac
}

# Nothing tailored to one machine: the collector's scripts name no home folder.
absent "a home folder in the collector's scripts" -rnF -e /Users/ -e '~/' scripts/event-level
# Nothing tailored to one stack, and the probe only reads a server: it runs no command inside
# a container and holds no rule for one product.
absent "a command run inside a container, or a rule for one product, in the probe" \
  -nF -e ' exec ' -e '##wp' -e '##pve' scripts/probe.sh
# Every commit runs the tests: the two halves of the check on GitHub name the test binaries
# and --bins, so a library target's unit tests would run in neither.
absent "a library target, whose tests neither half of ./check runs" -nF '[lib]' Cargo.toml
[ ! -e src/lib.rs ] || fail "src/lib.rs, a library target whose tests neither half of ./check runs"

# The pages are drawn from what the commands answer: no file that draws a page reads the store or
# takes the state the status is built from. Left out, as in the rule below, is a test module: a
# test may make a store to build the messages a page is drawn from.
if pages=$(git -c core.quotePath=false ls-files src/view.rs src/happens.rs src/not_read_here.rs \
  src/pages.rs 'src/pages/*.rs') && [ -n "$pages" ]; then
  if store=$(printf '%s\n' "$pages" | /usr/bin/tr '\n' '\0' | /usr/bin/xargs -0 /usr/bin/awk '
    skip { if ($0 ~ /^}/) skip = 0; next }
    test { test = 0; if ($0 ~ /^(pub(\([a-z]+\))? )?mod [a-z0-9_]+ \{$/) { skip = 1; next } }
    /^#\[cfg\(test\)\]$/ { test = 1 }
    /rusqlite|status::State/ { print FILENAME ":" FNR ": " $0 }'); then
    [ -z "$store" ] || fail "the store, or the status's state, in a file that draws a page: $store"
  else
    fail "could not read the files that draw a page, which are checked for the store"
  fi
else
  fail "could not list the files that draw a page, which are checked for the store"
fi

# Every file the core reads is opened one way, by src/open.rs. Left out: the store (SQLite and
# its locks), the install (service.rs), tests (a test module, or a `#[cfg(test)]` module, which
# rustfmt closes at the first column), and src/events.rs, whose readers of what the collector
# and its installer write (the log read by offset, the record of what is collected, the notes
# of what was removed) are not yet moved and are their own change.
sources=$(git -c core.quotePath=false ls-files 'src/*.rs') ||
  fail "could not list the sources, whose reads of files are checked"
if reads=$(printf '%s\n' "$sources" | /usr/bin/grep -vxE \
  'src/(open|store|service|events)\.rs|src/.*/tests(\.rs|/.*)' | /usr/bin/tr '\n' '\0' |
  /usr/bin/xargs -0 /usr/bin/awk '
  skip { if ($0 ~ /^}/) skip = 0; next }
  test { test = 0; if ($0 ~ /^(pub(\([a-z]+\))? )?mod [a-z0-9_]+ \{$/) { skip = 1; next } }
  /^#\[cfg\(test\)\]$/ { test = 1 }
  /File::open|fs::read\(|fs::read_to_string|\.read\(true\)/ { print FILENAME ":" FNR ": " $0 }'); then
  [ -z "$reads" ] || fail "a read of a file outside src/open.rs: $reads"
else
  fail "could not read the sources, whose reads of files are checked"
fi

# Every write to the store goes through one of its two ways in src/store.rs: `store::write`, which
# checks the store and takes the run lock, or `store::write_held`, for a step of the watcher, which
# holds the lock across its steps. Only a connection that can write writes, so the rule is held on
# where one is opened, in the same files and with the same tests left out as the rule above. Left
# out by name: the full check (`run`) and the watcher's two readings, which hold the lock and open
# the store themselves. A `use` of those functions, which would hide them under another name, is
# refused anywhere.
if writes=$(printf '%s\n' "$sources" | /usr/bin/grep -vxE \
  'src/store\.rs|src/.*/tests(\.rs|/.*)' | /usr/bin/tr '\n' '\0' |
  /usr/bin/xargs -0 /usr/bin/awk '
  FNR == 1 { fn = "" }
  skip { if ($0 ~ /^}/) skip = 0; next }
  test { test = 0; if ($0 ~ /^(pub(\([a-z]+\))? )?mod [a-z0-9_]+ \{$/) { skip = 1; next } }
  /^#\[cfg\(test\)\]$/ { test = 1 }
  match($0, /^ *(pub(\([a-z]+\))? )?fn [a-z0-9_]+/) {
    fn = substr($0, RSTART, RLENGTH); sub(/.* /, "", fn) }
  /store::(open|open_or_make)\(|Connection::open/ &&
    FILENAME ":" fn !~ /^src\/(main\.rs:(run|read_events_held)|watch\.rs:read_held)$/ ||
    /store::write_held\(/ && FILENAME ":" fn !~ /^src\/watch\.rs:(sample|mark)$/ ||
    /^ *use crate::store::.*(open|write_held)/ {
    print FILENAME ":" FNR ": " $0 }'); then
  [ -z "$writes" ] || fail "a write to the store outside store::write and store::write_held: $writes"
else
  fail "could not read the sources, whose writes to the store are checked"
fi

# The rules in the header of the check's workflow. Comments may name what is refused.
# A pull request from a fork never runs with the base repository's token and secrets.
absent "pull_request_target in a workflow" -rnE '^[^#]*pull_request_target' .github/workflows
# The cache's key is exact, so no run restores a cache saved under another lockfile.
absent "restore-keys in a workflow" -rnE '^[^#]*restore-keys' .github/workflows
# actions/cache restores and saves in every run; only its restore and save parts are used, so
# saving can be limited to main.
absent "actions/cache, which saves in every run, in a workflow" -rnE '^[^#]*actions/cache@' \
  .github/workflows
# The rules below read the workflows as text, so no text may stand for other text: no YAML
# escape or line joined by a backslash, no quoted key, no tab.
absent "a backslash in a workflow" -rnF '\' .github/workflows
absent "a quoted uses key in a workflow" -rnE "[\"']uses[\"']" .github/workflows
absent "a tab in a workflow" -rnF "$(printf '\t')" .github/workflows
# Every action is pinned by a full commit hash. A local action has none, so it is refused too.
if uses=$(/usr/bin/grep -rnE '^[^#]*uses[[:space:]]*:' .github/workflows); then
  unpinned=$(printf '%s\n' "$uses" |
    /usr/bin/grep -vE '^[^:]+:[0-9]+: *(- )?uses: [^@ ]+@[0-9a-f]{40}( #.*)?$')
  [ -z "$unpinned" ] || fail "an action not pinned by a full commit hash: $unpinned"
else
  fail "could not read the workflows, or none names an action"
fi
# Only a run for a push to main saves the cache. Its one step must be exactly this text, so
# whoever changes it changes this file in the same commit. A line indented deeper after it
# would belong to the step, so the next line that is not empty is indented less.
save_step=$(
  cat <<'STEP'
      - name: Save what main compiled
        if: github.event_name == 'push' && steps.cache.outputs.cache-hit != 'true'
        uses: actions/cache/save@caa296126883cff596d87d8935842f9db880ef25 # v5.1.0
        with:
          path: ${{ env.CACHED }}
          key: ${{ steps.cache.outputs.cache-primary-key }}
STEP
)
saves=$(/usr/bin/grep -rnoF cache/save .github/workflows)
if [ "$(printf '%s\n' "$saves" | /usr/bin/grep -c .)" -ne 1 ]; then
  fail "cache/save is not named exactly once in .github/workflows: ${saves:-nowhere}"
else
  file=${saves%%:*}
  at=${saves#*:}
  first=$((${at%%:*} - 2))
  [ "$first" -ge 1 ] && [ "$(/usr/bin/sed -n "$first,$((first + 5))p" "$file")" = "$save_step" ] &&
    ! /usr/bin/sed -n "$((first + 6)),\$p" "$file" | /usr/bin/grep -v '^ *$' | /usr/bin/head -1 |
    /usr/bin/grep -q '^       ' ||
    fail "$file: the step that saves the cache is not the one scripts/lint.sh holds"
fi

# No file is longer than one read of a file returns to an agent in the tools this project is
# built with, so an agent working on a file sees all of it. Counted is every file git holds as
# text, except Cargo.lock, the code generated from the schema and what lies under a folder
# holding a NOTICE, which is copied from another project. The files longer than that today are
# listed; the list only shrinks, and a file on it is split when it is next reworked.
ceiling=2000
longer_today='
src/answers_text.rs
src/autorun.rs
src/events.rs
src/finding_text.rs
src/findings.rs
src/lists.rs
src/main.rs
src/overview.rs
src/secrets.rs
src/sigma.rs
src/store.rs
src/vulnerabilities.rs
src/watch.rs
tests/event_level.rs
tests/matches.rs
tests/program_and_machine.rs
tests/promises.rs
tests/runs_by_itself.rs
tests/verdict.rs
tests/vulnerability_data.rs
tests/watch.rs
'
if held=$(git -c core.quotePath=false ls-files --eol); then
  counted=$(printf '%s\n' "$held" | /usr/bin/awk -F '\t' '
    $1 !~ /^i\/-text/ { file[++n] = $2 }
    $2 ~ /\/NOTICE$/ { copied[substr($2, 1, length($2) - 6)] = 1 }
    END { for (i = 1; i <= n; i++) { keep = 1; for (d in copied) if (index(file[i], d) == 1) keep = 0
      if (keep) print file[i] } }')
  over=
  while IFS= read -r f; do
    case $f in Cargo.lock | contract/src/immunity.v1.rs) continue ;; esac
    lines=$(/usr/bin/wc -l <"$f") || { fail "could not read $f to count its lines"; continue; }
    [ $((lines)) -le "$ceiling" ] && continue
    over="$over$f
"
    printf '%s\n' "$longer_today" | /usr/bin/grep -qxF -e "$f" ||
      fail "$f is longer than $ceiling lines, more than one read shows an agent: split it"
  done <<EOF
$counted
EOF
  while IFS= read -r f; do
    [ -z "$f" ] || printf '%s' "$over" | /usr/bin/grep -qxF -e "$f" || fail "$f is on the list" \
      "of files longer than $ceiling lines in scripts/lint.sh but is not, or is gone: take it off"
  done <<EOF
$longer_today
EOF
else
  fail "could not list the files git holds, whose length is checked"
fi

exit "$failed"
