#!/usr/bin/env bash
# ns-hc-isolate.sh — stage-B OS isolation driver for anything that can spawn
# hc / herdr-core / `<ctxmode> --hc-gate`.
#
# WHY THIS EXISTS (audit §3.1, contract §2.6 second layer)
#   The TestMain/inTestBinary pin only covers processes that actually ENTER
#   runHcGate. A rewrite failure, a manual `sh -c 'hc send …'`, an absolute
#   `/root/.local/bin/hc`, a hostile PATH or a login shell that resets PATH
#   never reaches the gate, so the pin cannot stop them. `.profile` /
#   `.bash_profile` are fixture hygiene, NOT an isolation control. Any test,
#   contract matrix, negative case or sub-shell that can produce a send must
#   therefore run under a REAL outer OS boundary: a private mount namespace in
#   which the host hc/herdr-core inode IS the recording stub.
#
# WHAT IT DOES
#   1. Outer: resolves the host hc target, captures host dev:ino, sha256 and a
#      /proc/self/mounts digest.
#   2. Enters `unshare -m --propagation private`.
#   3. Inner hard assertions (no `|| true`, no fallback):
#        - inner mount ns != host mount ns
#        - findmnt -n -o PROPAGATION -T "$HC_REAL" == "private"
#        - read-only bind of the stand-in ELF over the host hc target
#        - second PROPAGATION assertion still "private"
#        - inner dev:ino / sha256 equal the stand-in and differ from the host
#   4. Runs the caller's command inside that namespace.
#   5. Outer re-checks host dev:ino, sha256 and the mounts digest are unchanged.
#
# STAGE A STATUS: written, syntax-checked (`bash -n`) and NOT executed. Running
# it requires the parent agent's explicit stage-B approval.
#
# Usage:
#   ns-hc-isolate.sh --standin <stub-elf> [--real <host-hc>] [--stub-log <file>] \
#                    [--note <text>] -- <command> [args...]
#
# Defaults: --real = /root/.local/bin/herdr-core (resolved through symlinks)
#           --stub-log = a file next to the stand-in, exported as HC_STUB_LOG
set -euo pipefail

PROG=${0##*/}
die() { printf '%s: FATAL: %s\n' "$PROG" "$*" >&2; exit 1; }
note() { printf '%s: %s\n' "$PROG" "$*" >&2; }

need() { command -v "$1" >/dev/null 2>&1 || die "required tool missing: $1"; }

# ---------------------------------------------------------------- inner mode
if [[ ${1:-} == "--inner" ]]; then
  shift
  [[ $# -ge 1 ]] || die "inner mode needs a command"
  : "${NS_HC_REAL:?}" "${NS_STANDIN:?}" "${NS_HOST_NS:?}"
  : "${NS_HOST_DEVID:?}" "${NS_HOST_SHA:?}" "${NS_HOST_MOUNTS:?}"
  : "${NS_STANDIN_DEVID:?}" "${NS_STANDIN_SHA:?}"

  need findmnt
  need mount
  need sha256sum
  need stat
  need readlink

  inner_ns=$(readlink /proc/self/ns/mnt)
  [[ -n $inner_ns ]] || die "cannot read inner mount namespace"
  [[ $inner_ns != "$NS_HOST_NS" ]] || die "inner mount ns $inner_ns equals host $NS_HOST_NS (unshare did not isolate)"

  prop=$(findmnt -n -o PROPAGATION -T "$NS_HC_REAL") || die "findmnt failed for $NS_HC_REAL"
  [[ $prop == "private" ]] || die "propagation of $NS_HC_REAL is '$prop', want 'private'"

  mount --bind "$NS_STANDIN" "$NS_HC_REAL" || die "bind $NS_STANDIN -> $NS_HC_REAL failed"
  mount -o remount,bind,ro "$NS_HC_REAL" || die "remount,bind,ro $NS_HC_REAL failed"

  prop=$(findmnt -n -o PROPAGATION -T "$NS_HC_REAL") || die "findmnt failed after remount"
  [[ $prop == "private" ]] || die "propagation after remount is '$prop', want 'private'"

  inner_devid=$(stat -c '%d:%i' "$NS_HC_REAL") || die "stat $NS_HC_REAL failed"
  [[ $inner_devid == "$NS_STANDIN_DEVID" ]] || die "inner hc dev:ino $inner_devid != standin $NS_STANDIN_DEVID"
  [[ $inner_devid != "$NS_HOST_DEVID" ]] || die "inner hc dev:ino still the host inode $NS_HOST_DEVID"
  inner_sha=$(sha256sum "$NS_HC_REAL" | cut -d' ' -f1)
  [[ $inner_sha == "$NS_STANDIN_SHA" ]] || die "inner hc sha256 $inner_sha != standin $NS_STANDIN_SHA"
  [[ $inner_sha != "$NS_HOST_SHA" ]] || die "inner hc sha256 still the host binary"

  note "isolated: hc=$NS_HC_REAL sha256=$inner_sha (stand-in), propagation=private"
  exec "$@"
fi

# ---------------------------------------------------------------- outer mode
STANDIN=""; REAL_HC=""; STUB_LOG=""; NOTE=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --standin) STANDIN=${2:?}; shift 2 ;;
    --real)    REAL_HC=${2:?}; shift 2 ;;
    --stub-log) STUB_LOG=${2:?}; shift 2 ;;
    --note)    NOTE=${2:?}; shift 2 ;;
    --) shift; break ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ $# -ge 1 ]] || die "no command given (use -- <command> [args...])"
[[ -n $STANDIN ]] || die "--standin <stub-elf> is required"
[[ -z $NOTE ]] || note "$NOTE"

need unshare
need findmnt
need sha256sum
need stat
need readlink

REAL_HC=${REAL_HC:-/root/.local/bin/herdr-core}
[[ -e $REAL_HC ]] || die "host hc target not found: $REAL_HC"
REAL_HC=$(readlink -f "$REAL_HC") || die "cannot resolve $REAL_HC"
[[ -f $REAL_HC ]] || die "host hc target is not a regular file: $REAL_HC"
[[ -f $STANDIN ]] || die "stand-in not found: $STANDIN"
STANDIN=$(readlink -f "$STANDIN") || die "cannot resolve $STANDIN"

magic=$(head -c 4 "$STANDIN" | od -An -tx1 | tr -d ' \n')
[[ $magic == "7f454c46" ]] || die "stand-in $STANDIN is not an ELF binary (magic=$magic)"

host_devid=$(stat -c '%d:%i' "$REAL_HC")
host_sha=$(sha256sum "$REAL_HC" | cut -d' ' -f1)
host_mounts=$(sha256sum /proc/self/mounts | cut -d' ' -f1)
host_ns=$(readlink /proc/self/ns/mnt)
[[ -n $host_ns ]] || die "cannot read host mount namespace"

standin_devid=$(stat -c '%d:%i' "$STANDIN")
standin_sha=$(sha256sum "$STANDIN" | cut -d' ' -f1)
[[ $standin_devid != "$host_devid" ]] || die "stand-in IS the host hc inode"
[[ $standin_sha != "$host_sha" ]] || die "stand-in IS the host hc binary"

if [[ -n $STUB_LOG ]]; then
  mkdir -p "$(dirname "$STUB_LOG")" || die "cannot create stub log dir"
  : >"$STUB_LOG" || die "cannot truncate stub log $STUB_LOG"
  export HC_STUB_LOG=$STUB_LOG
fi

note "host hc $REAL_HC dev:ino=$host_devid sha256=$host_sha"
note "stand-in  $STANDIN dev:ino=$standin_devid sha256=$standin_sha"

export NS_HC_REAL=$REAL_HC NS_STANDIN=$STANDIN NS_HOST_NS=$host_ns
export NS_HOST_DEVID=$host_devid NS_HOST_SHA=$host_sha NS_HOST_MOUNTS=$host_mounts
export NS_STANDIN_DEVID=$standin_devid NS_STANDIN_SHA=$standin_sha

set +e
unshare -m --propagation private -- "$0" --inner "$@"
rc=$?
set -e

# Host invariants: the namespace must be gone and the host binary untouched.
now_devid=$(stat -c '%d:%i' "$REAL_HC")
now_sha=$(sha256sum "$REAL_HC" | cut -d' ' -f1)
now_mounts=$(sha256sum /proc/self/mounts | cut -d' ' -f1)
[[ $now_devid == "$host_devid" ]] || die "HOST CHANGED: $REAL_HC dev:ino $now_devid != $host_devid"
[[ $now_sha == "$host_sha" ]] || die "HOST CHANGED: $REAL_HC sha256 $now_sha != $host_sha"
[[ $now_mounts == "$host_mounts" ]] || die "HOST CHANGED: /proc/self/mounts digest differs"
note "host invariants preserved (dev:ino, sha256, mounts digest)"

exit "$rc"
