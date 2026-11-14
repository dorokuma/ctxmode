#!/usr/bin/env bash
# ns-hc-gotest.sh — stage-B runner: execute the WHOLE go test binary under the
# ns-hc-isolate.sh OS boundary, so no rewrite failure / hostile PATH / login
# shell / absolute-path spelling can ever reach the host herdr-core.
#
# STAGE A STATUS: written, syntax-checked (`bash -n`) and NOT executed. It runs
# `go test`, which stage A forbids outright; the parent agent approves stage B
# before this script is ever invoked.
#
# Usage:
#   scripts/ns-hc-gotest.sh [-C <repo>] [--race] [--timeout <d>] [-- <go test args>]
#
# It records git rev-parse HEAD, HEAD^{tree} and a clean `git status
# --porcelain` in the log header (contract §2.6 / stage C attribution), builds
# the recording stub outside the repo, then runs
#   ns-hc-isolate.sh --standin <stub> --real <host hc> -- go test …
set -euo pipefail

REPO=${PWD}
RACE=0
TIMEOUT=30m
LOG=${NS_GOTEST_LOG:-/root/ctxmode-merge-jobs/hcfix-stage-a-1114c-fileonly/ns-gotest.log}

while [[ $# -gt 0 ]]; do
  case $1 in
    -C) REPO=${2:?}; shift 2 ;;
    --race) RACE=1; shift ;;
    --timeout) TIMEOUT=${2:?}; shift 2 ;;
    --log) LOG=${2:?}; shift 2 ;;
    --) shift; break ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) break ;;
  esac
done

die() { printf '%s: FATAL: %s\n' "${0##*/}" "$*" >&2; exit 1; }
command -v go >/dev/null 2>&1 || die "go toolchain missing"

cd "$REPO" || die "cannot cd $REPO"
[[ -d .git || -f .git ]] || die "$REPO is not a git worktree"

HEAD_SHA=$(git rev-parse HEAD)
TREE_SHA=$(git rev-parse 'HEAD^{tree}')
PORCELAIN=$(git status --porcelain || true)

mkdir -p "$(dirname "$LOG")" || die "cannot create log dir"
{
  echo "# ns-hc-gotest $(date -Is)"
  echo "# repo=$REPO"
  echo "# HEAD=$HEAD_SHA"
  echo "# tree=$TREE_SHA"
  if [[ -z $PORCELAIN ]]; then
    echo "# status=clean"
  else
    echo "# status=DIRTY"
    printf '%s\n' "$PORCELAIN" | sed 's/^/#   /'
  fi
} | tee -a "$LOG" >&2

WORK=$(mktemp -d /tmp/hcfix-ns-gotest-XXXXXX) || die "mktemp failed"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

cat >"$WORK/stub.go" <<'STUB'
// Recording hc stand-in: appends its argv (JSON) to HC_STUB_LOG and exits 0.
// The fixed CTXMODE-NS-HC-STANDIN tag is what TestMain's
// mustVerifyOuterTestIsolation greps for inside every masked
// hc/herdr-core/sbx path: a path that serves bytes WITHOUT the tag is the
// real host binary (mask missing) and the gate refuses to run.
package main

import (
	"encoding/json"
	"os"
)

const standinTag = "CTXMODE-NS-HC-STANDIN"

func main() {
	path := os.Getenv("HC_STUB_LOG")
	if path == "" {
		os.Exit(2)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(3)
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(append([]string{standinTag}, os.Args...))
}
STUB

STUB_BIN=$WORK/herdr-core
GOTOOLCHAIN=local go build -o "$STUB_BIN" "$WORK/stub.go" || die "stub build failed"

STUB_LOG=$WORK/hc-stub-calls.jsonl

GO_ARGS=(test)
if [[ -n $TIMEOUT ]]; then
  GO_ARGS+=(-timeout "$TIMEOUT")
fi
if [[ $RACE -eq 1 ]]; then
  GO_ARGS+=(-race)
fi
GO_ARGS+=("./...")
if [[ $# -gt 0 ]]; then
  GO_ARGS+=("$@")
fi

HOST_HC=${NS_HOST_HC:-/root/.local/bin/herdr-core}

# No CTXMODE_TEST_* names are exported into the payload: the outer boundary
# is kernel state (mount ns + ro stand-in + dropped caps + private /proc),
# and the only outward escape evidence is the stand-in's own recording log.
# In-test --hc-gate children still arm their pin through each test's own
# newHcE2E/withIsolatedHcPath helpers.
set +e
"$REPO/scripts/ns-hc-isolate.sh" \
  --standin "$STUB_BIN" \
  --real "$HOST_HC" \
  --stub-log "$STUB_LOG" \
  --note "go test $HEAD_SHA" \
  -- env HC_STUB_LOG="$STUB_LOG" go "${GO_ARGS[@]}" 2>&1 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
set -e

{
  echo "# rc=$rc"
  if [[ -s $STUB_LOG ]]; then
    echo "# stub calls:"
    sed 's/^/#   /' "$STUB_LOG"
  else
    echo "# stub calls: none"
  fi
  echo "# after: HEAD=$(git rev-parse HEAD) tree=$(git rev-parse 'HEAD^{tree}')"
} | tee -a "$LOG" >&2

exit "$rc"
