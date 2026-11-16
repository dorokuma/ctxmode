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
#   therefore run under a REAL outer OS boundary: a private mount+PID+net
#   namespace in which every host hc/herdr-core/sbx inode IS the recording
#   stand-in, capabilities are dropped, and noNewPrivs is set.
#
# WHAT IT DOES
#   1. Outer: enumerates every hc/herdr-core/sbx entry across the trusted
#      bin dirs AND the caller's PATH (resolving each through readlink -f),
#      captures dev:ino + sha256 for the primary --real target and a mounts
#      digest.
#   2. Enters `unshare --mount --pid --net --fork --propagation private`.
#   3. Inner hard assertions (no `|| true`, no fallback):
#        - inner mount ns != host mount ns; inner PID ns has a private /proc
#          (mount --make-rprivate / ; mount -t proc proc /proc)
#        - findmnt -n -o PROPAGATION -T <target> == "private" before AND
#          after every bind
#        - read-only bind of the stand-in ELF over EVERY enumerated target
#          (plus its readlink -f resolution, deduplicated)
#        - a read-only empty tmpfs over the host herdr runtime socket dir
#          when present
#        - inner dev:ino / sha256 equal the stand-in and differ from host
#   4. Drops privileges with setpriv --no-new-privs --inh-caps=-all
#      --ambient-caps=-all --bounding-set=-all and runs the caller's command.
#   5. Outer re-checks host dev:ino, sha256 and the mounts digest are
#      unchanged.
#
# STAGE A STATUS: written, syntax-checked (`bash -n`) and NOT executed.
# Running it requires the parent agent's explicit stage-B approval.
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

# Trusted bin dirs + the caller's PATH: every hc/herdr-core/sbx entry under
# them must end up masked. Each entry is emitted ONLY as its readlink -f
# canonical path (deduplicated): mount --bind follows symlinks, so feeding
# the unresolved symlink path AND the resolved path would stack two bind
# mounts on the same dentry — masking the real inode once already makes
# every symlink that points at it resolve to the stand-in. Passed to the
# inner phase as a newline-separated list via NS_TARGETS.
enumerate_targets() {
  local dirs d name p resolved
  declare -A seen=()
  for d in /root/.local/bin /root/bin /root/.cargo/bin \
           /root/.local/share/mise/shims \
           /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
    seen[$d]=1
  done
  local IFS=':'
  for d in $PATH; do
    [[ -n $d && $d == /* ]] && seen[$d]=1
  done
  unset IFS
  for name in hc herdr-core sbx; do
    for d in "${!seen[@]}"; do
      p=$d/$name
      if [[ -e $p && ! -d $p ]]; then
        resolved=$(readlink -f "$p" 2>/dev/null || true)
        if [[ -z $resolved || ! -f $resolved ]]; then
          die "cannot resolve enumerated target to a regular file: $p"
        fi
        printf '%s\n' "$resolved"
      fi
    done
  done | sort -u
}

# ---------------------------------------------------------------- inner mode
if [[ ${1:-} == "--inner" ]]; then
  shift
  [[ $# -ge 1 ]] || die "inner mode needs a command"
  : "${NS_STANDIN:?}" "${NS_HOST_NS:?}"
  : "${NS_STANDIN_DEVID:?}" "${NS_STANDIN_SHA:?}"
  : "${NS_HOST_DEVID:?}" "${NS_HOST_SHA:?}"
  : "${NS_TARGETS:?}"

  need findmnt
  need mount
  need sha256sum
  need stat
  need readlink
  need setpriv

  inner_ns=$(readlink /proc/self/ns/mnt)
  [[ -n $inner_ns ]] || die "cannot read inner mount namespace"
  [[ $inner_ns != "$NS_HOST_NS" ]] || die "inner mount ns $inner_ns equals host $NS_HOST_NS (unshare did not isolate)"

  # Private propagation for every mount we inherited, then a fresh private
  # /proc so /proc/1 is the inner init (the payload), not the host's
  # systemd/init — that is what TestMain's mustVerifyOuterTestIsolation
  # asserts.
  mount --make-rprivate / || die "mount --make-rprivate / failed"
  mount -t proc proc /proc || die "private /proc mount failed"

  mask_one() {
    local target=$1 prop inner_devid inner_sha
    prop=$(findmnt -n -o PROPAGATION -T "$target") || die "findmnt failed for $target"
    [[ $prop == "private" ]] || die "propagation of $target is '$prop', want 'private'"

    mount --bind "$NS_STANDIN" "$target" || die "bind $NS_STANDIN -> $target failed"
    mount -o remount,bind,ro "$target" || die "remount,bind,ro $target failed"

    prop=$(findmnt -n -o PROPAGATION -T "$target") || die "findmnt failed after remount for $target"
    [[ $prop == "private" ]] || die "propagation after remount is '$prop', want 'private'"

    inner_devid=$(stat -c '%d:%i' "$target") || die "stat $target failed"
    [[ $inner_devid == "$NS_STANDIN_DEVID" ]] || die "inner $target dev:ino $inner_devid != standin $NS_STANDIN_DEVID"
    [[ $inner_devid != "$NS_HOST_DEVID" ]] || die "inner $target dev:ino still the host inode $NS_HOST_DEVID"
    inner_sha=$(sha256sum "$target" | cut -d' ' -f1)
    [[ $inner_sha == "$NS_STANDIN_SHA" ]] || die "inner $target sha256 $inner_sha != standin $NS_STANDIN_SHA"
    [[ $inner_sha != "$NS_HOST_SHA" ]] || die "inner $target sha256 still the host binary"
    note "masked: $target -> stand-in (ro, private)"
  }

  # Bind the read-only stand-in over EVERY enumerated hc/herdr-core/sbx
  # path (already resolved + deduplicated by the outer phase).
  while IFS= read -r target; do
    [[ -n $target ]] || continue
    [[ -e $target ]] || die "enumerated target vanished inside ns: $target"
    mask_one "$target"
  done <<< "$NS_TARGETS"

  # Seal the host herdr runtime socket directory (if it exists): a test
  # child must never reach a running host herdr-core through its socket.
  for sockdir in /root/.local/state/herdr /root/.local/run/herdr /run/herdr-core; do
    if [[ -d $sockdir ]]; then
      mount -t tmpfs -o ro,nosuid,nodev tmpfs "$sockdir" || die "tmpfs mask of $sockdir failed"
      note "masked socket dir: $sockdir (ro tmpfs)"
    fi
  done

  note "isolated: ${#@} payload word(s), all targets masked, propagation=private"
  # Full privilege drop: no-new-privs + zeroed capability sets, then exec.
  exec setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- "$@"
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
    -h|--help) sed -n '2,50p' "$0"; exit 0 ;;
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

# The enumeration runs on the HOST (the mount table the payload would see
# unmasked). Every line is masked inside the namespace.
mapfile -t NS_TARGET_LIST < <(enumerate_targets)
((${#NS_TARGET_LIST[@]} > 0)) || die "no hc/herdr-core/sbx targets enumerated on host PATH/trusted dirs"
# The --real resolution must be in the set (it always is via
# /root/.local/bin, but keep the invariant explicit).
found_real=0
for t in "${NS_TARGET_LIST[@]}"; do
  [[ $t == "$REAL_HC" ]] && found_real=1
done
[[ $found_real -eq 1 ]] || NS_TARGET_LIST+=("$REAL_HC")
NS_TARGETS=$(printf '%s\n' "${NS_TARGET_LIST[@]}")
printf '%s\n' "$NS_TARGETS" | sed 's/^/  target: /' >&2

if [[ -n $STUB_LOG ]]; then
  mkdir -p "$(dirname "$STUB_LOG")" || die "cannot create stub log dir"
  : >"$STUB_LOG" || die "cannot truncate stub log $STUB_LOG"
  export HC_STUB_LOG=$STUB_LOG
fi

note "host hc $REAL_HC dev:ino=$host_devid sha256=$host_sha"
note "stand-in  $STANDIN dev:ino=$standin_devid sha256=$standin_sha"

export NS_STANDIN=$STANDIN NS_HOST_NS=$host_ns
export NS_HOST_DEVID=$host_devid NS_HOST_SHA=$host_sha
export NS_STANDIN_DEVID=$standin_devid NS_STANDIN_SHA=$standin_sha
export NS_TARGETS

set +e
unshare --mount --pid --net --fork --propagation private -- "$0" --inner "$@"
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
