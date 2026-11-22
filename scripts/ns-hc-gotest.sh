#!/usr/bin/env bash
# ns-hc-gotest.sh — run the WHOLE go test suite inside the ns-hc-isolate.sh
# OS boundary, so no rewrite failure / hostile PATH / login shell /
# absolute-path spelling can ever reach the host herdr-core. It is the
# Makefile `check` test driver and the only approved way to run this
# package's tests: TestMain's mustVerifyOuterTestIsolation refuses a bare
# `go test` with exit 125, so the suite can only pass under this script.
#
# Usage:
#   scripts/ns-hc-gotest.sh [-C <repo>] [--race] [--timeout <d>] [--log <file>] \
#                           [-- <go test args>]
#
# It records git rev-parse HEAD, HEAD^{tree} and a clean `git status
# --porcelain` in the log header (stage C attribution), builds the
# recording stand-in stub inside a mktemp work dir, then runs
#   ns-hc-isolate.sh --standin <stub> --real <host hc> -- go test …
#
# Logging: --log or NS_GOTEST_LOG picks a persistent log file (its parent
# dir is created). With neither, the log lives inside the mktemp work dir
# and is cleaned up with it on EXIT — nothing is written outside /tmp
# unless the caller asked for it.
# Host hc resolution: NS_HOST_HC wins; otherwise the first existing
# non-directory of /root/.local/bin/herdr-core, /usr/local/bin/herdr-core,
# `command -v herdr-core`, `command -v hc` is used. No candidate → die.
set -euo pipefail

REPO=${PWD}
RACE=0
TIMEOUT=30m
LOG=${NS_GOTEST_LOG:-}
LOG_EXPLICIT=0
if [[ -n $LOG ]]; then
  LOG_EXPLICIT=1
fi

while [[ $# -gt 0 ]]; do
  case $1 in
    -C) REPO=${2:?}; shift 2 ;;
    --race) RACE=1; shift ;;
    --timeout) TIMEOUT=${2:?}; shift 2 ;;
    --log) LOG=${2:?}; LOG_EXPLICIT=1; shift 2 ;;
    --) shift; break ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
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

# Work dir first so an unset --log/NS_GOTEST_LOG can default into it and be
# cleaned up automatically; an explicit log path is created persistently.
WORK=$(mktemp -d /tmp/hcfix-ns-gotest-XXXXXX) || die "mktemp failed"
# 0700, not 0755: the work dir holds the stand-in stub that gets
# bind-mounted over trusted hc/herdr-core slots. mktemp already
# creates it 0700 — do NOT open it up: a 0755 /tmp dir would let any
# local user rewrite the stub during the test window. The payload either
# runs as root (outer path) or drops back to the CALLER_UID who owns
# this dir, so 0700 blocks everyone else and costs nothing.
chmod 0700 "$WORK"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

if [[ $LOG_EXPLICIT -eq 1 ]]; then
  mkdir -p "$(dirname "$LOG")" || die "cannot create log dir for $LOG"
else
  LOG="$WORK/ns-gotest.log"
fi

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

cat >"$WORK/stub.go" <<'STUB'
// Recording hc stand-in: appends its argv (JSON) to HC_STUB_LOG and exits 0.
// The fixed CTXMODE-NS-HC-STANDIN tag is what TestMain's
// mustVerifyOuterTestIsolation greps for inside every masked
// hc/herdr-core path: a path that serves bytes WITHOUT the tag is the
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
# Build the stub outside the module context: inside the repo `go build`
# picks up go.mod's `go 1.26.0` directive and a too-old local toolchain
# (e.g. GOTOOLCHAIN=local go1.24) refuses to compile. The stub is
# self-contained stdlib, so building it from the mktemp dir (no go.mod)
# with the ambient toolchain always works.
(cd "$WORK" && go build -o "$STUB_BIN" stub.go) || die "stub build failed"
chmod 0755 "$STUB_BIN"

STUB_LOG=$WORK/hc-stub-calls.jsonl
: >"$STUB_LOG" && chmod 0600 "$STUB_LOG"

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

# Resolve the host hc that the namespace will mask (and re-verify after).
# NS_HOST_HC wins explicitly; the probes cover the maintainer host
# (/root/.local/bin), the CI runner (/usr/local/bin) and a PATH-resolvable
# herdr-core/hc, in that order. A missing or directory candidate is
# skipped; no candidate at all fails closed.
# SYMMETRY with ns-hc-isolate.sh NS_SEAL_ROOT: a non-root caller working
# outside /root can never reach /root/* inside the sealed namespace, so
# a /root/* candidate (direct, or one whose readlink -f resolves into
# /root) is skipped here exactly like the isolate script skips it.
nonroot_outside_root() {
  [[ $(id -u) -ne 0 && $PWD != /root && $PWD != /root/* ]]
}
host_hc_candidate_ok() {
  local cand=$1
  [[ -e $cand && ! -d $cand ]] || return 1
  if nonroot_outside_root; then
    [[ $cand != /root && $cand != /root/* ]] || return 1
    local resolved
    resolved=$(readlink -f "$cand" 2>/dev/null || true)
    if [[ -n $resolved ]]; then
      [[ $resolved != /root && $resolved != /root/* ]] || return 1
    fi
  fi
  return 0
}
HOST_HC=${NS_HOST_HC:-}
if [[ -z $HOST_HC ]]; then
  for cand in /root/.local/bin/herdr-core /usr/local/bin/herdr-core; do
    if host_hc_candidate_ok "$cand"; then
      HOST_HC=$cand
      break
    fi
  done
fi
if [[ -z $HOST_HC ]]; then
  for name in herdr-core hc; do
    cand=$(command -v "$name" 2>/dev/null || true)
    if [[ -n $cand ]] && host_hc_candidate_ok "$cand"; then
      HOST_HC=$cand
      break
    fi
  done
fi
[[ -n $HOST_HC ]] || die "no host hc found (set NS_HOST_HC; probed /root/.local/bin, /usr/local/bin, PATH)"

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
