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

exit "$failed"
