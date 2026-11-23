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

exit "$failed"
