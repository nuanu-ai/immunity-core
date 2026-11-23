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

# The rules in the header of the check's workflow. Comments may name what is refused.
# A pull request from a fork never runs with the base repository's token and secrets.
absent "pull_request_target in a workflow" -rnE '^[^#]*pull_request_target' .github/workflows
# The cache's key is exact, so no run restores a cache saved under another lockfile.
absent "restore-keys in a workflow" -rnE '^[^#]*restore-keys' .github/workflows
# actions/cache restores and saves in every run; only its restore and save parts are used, so
# saving can be limited to main.
absent "actions/cache, which saves in every run, in a workflow" -rnE '^[^#]*actions/cache@' \
  .github/workflows
# Every action is pinned by a full commit hash, and only a run for a push to main saves the
# cache: a step that names actions/cache/save carries, at its own level, an `if:` that begins
# with that condition and holds no `||` that could make it true otherwise. The file is read by
# line: a step is a `- ` at the indentation of the first item under `steps:`, up to the next
# one or the first line indented less. A save step written in another form is refused.
end_step() {
  [ -z "$save" ] || [ -n "$guarded" ] ||
    fail "$workflow:$save: a step that saves the cache without if: github.event_name == 'push'"
  save="" guarded=""
}
for workflow in .github/workflows/*; do
  if ! [ -f "$workflow" ] || ! [ -r "$workflow" ]; then
    fail "could not read $workflow"
    continue
  fi
  steps="" item="" save="" guarded="" n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    text=${line#"${line%%[! ]*}"}
    indent=$((${#line} - ${#text}))
    case $text in '' | '#'*) continue ;; esac
    if [ -n "$steps" ] && [ "$indent" -le "$steps" ]; then
      end_step
      steps="" item=""
    fi
    case $text in steps:*) steps=$indent item="" ;; esac
    if [ -n "$steps" ] && [ "$indent" -gt "$steps" ]; then
      case $text in
        '- '*) if [ -z "$item" ] || [ "$indent" -eq "$item" ]; then
          end_step
          item=$indent
        fi ;;
      esac
    fi
    key=${text#- }
    case $text in
      *uses:*)
        action=${text#*uses:}
        action=${action#"${action%%[! ]*}"}
        printf '%s\n' "$action" | /usr/bin/grep -qE '^[^@ ]+@[0-9a-f]{40}( |$)' ||
          fail "$workflow:$n: an action not pinned by a full commit hash"
        ;;
    esac
    case $text in
      *actions/cache/save*)
        [ -n "$item" ] && [ -n "$steps" ] || fail "$workflow:$n: actions/cache/save outside a step"
        save=$n
        ;;
    esac
    if [ -n "$item" ] && [ "$((indent + ${#text} - ${#key}))" -eq "$((item + 2))" ]; then
      case $key in
        "if: github.event_name == 'push'" | "if: github.event_name == 'push' &&"*)
          case $key in *'||'*) ;; *) guarded=$n ;; esac
          ;;
      esac
    fi
  done <"$workflow"
  end_step
done

exit "$failed"
