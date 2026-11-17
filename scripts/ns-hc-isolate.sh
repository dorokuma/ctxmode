#!/usr/bin/env bash
# ns-hc-isolate.sh — OS isolation driver for anything that can spawn
# hc / herdr-core / `<ctxmode> --hc-gate`. It is the outer boundary the
# whole test suite runs under via ns-hc-gotest.sh / `make check`.
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
#   1. Outer: parses args and validates them BEFORE any privilege step, so
#      CLI misuse fails without sudo. A non-root caller is re-exec'd through
#      `sudo -n env …` with an EXPLICIT env passthrough (never sudo -E, so
#      sudoers SETENV/secure_path cannot strip PATH/TMPDIR/GOFLAGS/etc.),
#      carrying NS_CALLER_UID/NS_CALLER_GID for the final privilege drop.
#   2. Outer (as root): enumerates every hc/herdr-core/sbx entry across the
#      trusted bin dirs AND the caller's PATH (resolving each through
#      readlink -f), captures dev:ino + sha256 for the primary --real
#      target and a mounts digest. For a non-root caller working outside
#      /root (NS_SEAL_ROOT=1) /root/* enumeration candidates and
#      /root/* --real probes are skipped — the payload will never be able
#      to resolve them, because the inner phase mounts a read-only empty
#      tmpfs over /root (ENOENT, never EACCES).
#   3. Enters `unshare --mount --pid --net --fork --propagation private`.
#   4. Inner hard assertions (no `|| true`, no fallback):
#        - inner mount ns != host mount ns; inner PID ns has a private /proc
#          (mount --make-rprivate / ; mount -t proc proc /proc)
#        - NS_SEAL_ROOT=1: ro nosuid nodev tmpfs over /root, propagation
#          verified private via findmnt
#        - findmnt -n -o PROPAGATION -T <target> == "private" before AND
#          after every bind
#        - read-only bind of the stand-in ELF over EVERY enumerated target
#          (plus its readlink -f resolution, deduplicated)
#        - a read-only empty tmpfs over the host herdr runtime socket dir
#          when present
#        - inner dev:ino / sha256 equal the stand-in and differ from host
#   5. Drops privileges with setpriv --no-new-privs --inh-caps=-all
#      --ambient-caps=-all --bounding-set=-all (plus --reuid/--regid/
#      --clear-groups for a non-root caller) and execs the payload.
#   6. Outer re-checks host dev:ino, sha256 and the mounts digest are
#      unchanged.
#
# Usage:
#   ns-hc-isolate.sh --standin <stub-elf> [--real <host-hc>] [--stub-log <file>] \
#                    [--note <text>] -- <command> [args...]
#
# Defaults: --real = first existing non-dir of the two fixed slots
#           /root/.local/bin/herdr-core, /usr/local/bin/herdr-core (no
#           `command -v` fallback here — PATH probing is ns-hc-gotest.sh's
#           job, it passes the resolved path via --real; a custom host hc
#           location must also be passed explicitly via --real). A non-root
#           caller outside /root skips candidates that live under /root/*
#           OR resolve (readlink -f) into /root/*.
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
# inner phase as a newline-separated list via NS_TARGETS. With
# NS_SEAL_ROOT=1 the inner phase mounts a ro empty tmpfs over /root, so
# /root/* candidates are skipped here (unresolvable there anyway).
enumerate_targets() {
  local d name p resolved
  declare -A seen=()
  # Dedup in-function (no `| sort -u` pipeline): a die() inside a pipeline
  # subshell or a process-substitution producer would only kill that
  # subshell and its status would be silently swallowed — the caller
  # captures this function via plain command substitution so every die
  # propagates as a non-zero exit.
  declare -A out_seen=()
  for d in /root/.local/bin /root/bin /root/.cargo/bin \
           /root/.local/share/mise/shims \
           /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
    [[ ${NS_SEAL_ROOT:-0} == 1 && $d == /root ]] && continue
    [[ ${NS_SEAL_ROOT:-0} == 1 && $d == /root/* ]] && continue
    seen[$d]=1
  done
  local IFS=':'
  for d in $PATH; do
    [[ -n $d && $d == /* ]] || continue
    [[ ${NS_SEAL_ROOT:-0} == 1 && $d == /root ]] && continue
    [[ ${NS_SEAL_ROOT:-0} == 1 && $d == /root/* ]] && continue
    seen[$d]=1
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
        # NS_SEAL_ROOT=1: a symlink can resolve INTO /root (e.g.
        # /usr/local/bin/hc -> /root/.local/bin/herdr-core). The sealed
        # tmpfs makes that target unreachable inside, so it is skipped
        # here — inside the namespace the link is simply dangling, which
        # is exactly what the gate expects (ENOENT, not a masked file).
        [[ ${NS_SEAL_ROOT:-0} == 1 && $resolved == /root/* ]] && continue
        out_seen[$resolved]=1
      fi
    done
  done
  for p in "${!out_seen[@]}"; do
    printf '%s\n' "$p"
  done
}

# Environment variables an unprivileged re-exec must carry through sudo.
# sudo -E is deliberately NOT used: it depends on sudoers SETENV and lets
# secure_path replace PATH. `env` passes only what is actually set; each
# variable that is set is emitted as one NUL-terminated NAME=VAL record.
ns_sudo_env_args() {
  local v
  for v in USER LOGNAME TMPDIR CI GOFLAGS GOPATH GOMODCACHE GOCACHE GOROOT \
           GOTOOLCHAIN CGO_ENABLED XDG_CACHE_HOME XDG_CONFIG_HOME \
           XDG_STATE_HOME HC_STUB_LOG LANG LC_ALL; do
    if [[ -n ${!v+x} ]]; then
      printf '%s=%s\0' "$v" "${!v}"
    fi
  done
}

# ---------------------------------------------------------------- inner mode
if [[ ${1:-} == "--inner" ]]; then
  shift
  [[ $# -ge 1 ]] || die "inner mode needs a command"
  : "${NS_STANDIN:?}" "${NS_HOST_NS:?}"
  : "${NS_STANDIN_DEVID:?}" "${NS_STANDIN_SHA:?}"
  : "${NS_HOST_DEVID:?}" "${NS_HOST_SHA:?}"
  : "${NS_TARGETS:?}"
  NS_CALLER_UID=${NS_CALLER_UID:-0}
  NS_CALLER_GID=${NS_CALLER_GID:-0}
  [[ $NS_CALLER_UID =~ ^[0-9]+$ ]] || die "NS_CALLER_UID must be numeric, got ${NS_CALLER_UID@Q}"
  [[ $NS_CALLER_GID =~ ^[0-9]+$ ]] || die "NS_CALLER_GID must be numeric, got ${NS_CALLER_GID@Q}"

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

  # The private net namespace has a loopback device but it is DOWN —
  # `unshare --net` never brings it up. Tests that bind an httptest/
  # 127.0.0.1 listener get EHOSTUNREACH until lo is raised. This is still
  # fully isolated: lo only reaches the namespace itself, there are no
  # external routes. If `ip` is unavailable the namespace still works for
  # everything that does not need loopback, so warn rather than die.
  if command -v ip >/dev/null 2>&1; then
    ip link set lo up 2>/dev/null || note "warning: could not bring loopback up"
  fi

  # findmnt -T on a STACKED mountpoint prints one line per layer (e.g.
  # multiple tmpfs/bind mounts over the same path): every layer's
  # propagation must be "private". The old `[[ $prop == "private" ]]`
  # single-value test misfired on two or more "private" lines, so this
  # helper loops over each line and dies on ANY non-private layer — the
  # check is strictly stronger, never weaker.
  # NOTE: `findmnt -T <path>` walks UP to the nearest mountpoint — a plain
  # file target (an hc/herdr-core/sbx slot being bind-masked) resolves to
  # the mountpoint that hosts it (e.g. `/`), which is the propagation that
  # actually decides whether our mounts leak back to the host.
  assert_private_propagation() {
    local target=$1 prop layer
    prop=$(findmnt -n -o PROPAGATION -T "$target") || die "findmnt failed for $target"
    [[ -n $prop ]] || die "findmnt returned no PROPAGATION for $target"
    while IFS= read -r layer; do
      [[ $layer == "private" ]] || die "propagation of $target is '$layer', want 'private' on every stacked layer"
    done <<< "$prop"
  }

  # Seal the host /root for a non-root caller: a read-only EMPTY tmpfs, so
  # every /root/* path (host hc fixtures, auth files, runtime state) is
  # simply absent inside the namespace — os.Lstat sees ENOENT, never a
  # permissive-but-unreadable EACCES. Skipped entirely for a root caller
  # (NS_SEAL_ROOT=0): the host hc lives under /root/.local/bin and must
  # stay visible so it can be bind-masked below.
  if [[ ${NS_SEAL_ROOT:-0} == 1 && -d /root ]]; then
    mount -t tmpfs -o ro,nosuid,nodev,mode=0555 tmpfs /root \
      || die "tmpfs seal of /root failed"
    assert_private_propagation /root
    note "sealed: /root -> ro empty tmpfs (NS_SEAL_ROOT=1)"
  fi

  mask_one() {
    local target=$1 inner_devid inner_sha
    assert_private_propagation "$target"

    mount --bind "$NS_STANDIN" "$target" || die "bind $NS_STANDIN -> $target failed"
    mount -o remount,bind,ro "$target" || die "remount,bind,ro $target failed"

    assert_private_propagation "$target"

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
    [[ ${NS_SEAL_ROOT:-0} == 1 && $sockdir == /root ]] && continue
    [[ ${NS_SEAL_ROOT:-0} == 1 && $sockdir == /root/* ]] && continue
    if [[ -d $sockdir ]]; then
      mount -t tmpfs -o ro,nosuid,nodev tmpfs "$sockdir" || die "tmpfs mask of $sockdir failed"
      note "masked socket dir: $sockdir (ro tmpfs)"
    fi
  done

  note "isolated: ${#@} payload word(s), all targets masked, propagation=private"
  # Full privilege drop: no-new-privs + zeroed capability sets, then exec.
  # A non-root caller additionally drops uid/gid/groups so the payload runs
  # with the caller's identity, not root's.
  if [[ $NS_CALLER_UID != 0 ]]; then
    exec setpriv --reuid="$NS_CALLER_UID" --regid="$NS_CALLER_GID" \
      --clear-groups --no-new-privs \
      --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- "$@"
  fi
  exec setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- "$@"
fi

# ---------------------------------------------------------------- outer mode
STANDIN=""; REAL_HC=""; STUB_LOG=""; NOTE=""
ORIG_ARGS=("$@")
while [[ $# -gt 0 ]]; do
  case $1 in
    --standin) [[ $# -ge 2 && -n $2 ]] || die "option $1 requires a STANDIN argument"; STANDIN=$2; shift 2 ;;
    --real)    [[ $# -ge 2 && -n $2 ]] || die "option $1 requires a REAL argument";    REAL_HC=$2;  shift 2 ;;
    --stub-log) [[ $# -ge 2 && -n $2 ]] || die "option $1 requires a STUB_LOG argument"; STUB_LOG=$2; shift 2 ;;
    --note)    [[ $# -ge 2 && -n $2 ]] || die "option $1 requires a NOTE argument";    NOTE=$2;    shift 2 ;;
    --) shift; break ;;
    -h|--help) sed -n '2,55p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ $# -ge 1 ]] || die "no command given (use -- <command> [args...])"
[[ -n $STANDIN ]] || die "--standin <stub-elf> is required"
[[ -z $NOTE ]] || note "$NOTE"
# Argument validation stays BEFORE the sudo re-exec: a missing stand-in
# is a CLI error and must fail without ever asking sudo for anything.
[[ -f $STANDIN ]] || die "stand-in not found: $STANDIN"

# Privilege step: unshare + mount + setpriv all need root. A non-root
# caller re-execs through `sudo -n` with an EXPLICIT env passthrough —
# never `sudo -E`, which depends on sudoers SETENV and lets secure_path
# replace PATH. NS_CALLER_UID/GID remember who to drop back to.
if [[ $(id -u) -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 \
    || die "non-root caller needs passwordless sudo (sudo not found)"
  sudo -n true 2>/dev/null \
    || die "non-root caller needs passwordless sudo (sudo -n true failed)"
  # Build the explicit passthrough list: PATH and HOME always, plus every
  # passthrough var that is actually set in the caller's environment.
  ENV_ARGS=(PATH="$PATH" HOME="$HOME")
  while IFS= read -r -d '' kv; do
    ENV_ARGS+=("$kv")
  done < <(ns_sudo_env_args)
  ENV_ARGS+=(NS_CALLER_UID="$(id -u)" NS_CALLER_GID="$(id -g)")
  exec sudo -n -- env "${ENV_ARGS[@]}" "$0" "${ORIG_ARGS[@]}"
fi

# Reached as root (directly or via the sudo re-exec).
CALLER_UID=${NS_CALLER_UID:-0}
CALLER_GID=${NS_CALLER_GID:-0}
[[ $CALLER_UID =~ ^[0-9]+$ ]] || die "NS_CALLER_UID must be numeric, got ${CALLER_UID@Q}"
[[ $CALLER_GID =~ ^[0-9]+$ ]] || die "NS_CALLER_GID must be numeric, got ${CALLER_GID@Q}"

need unshare
need findmnt
need sha256sum
need stat
need readlink

# NS_SEAL_ROOT: a non-root caller working outside /root gets /root sealed
# with a ro empty tmpfs inside the namespace. That is only valid when the
# --real host hc AND the stand-in are both outside /root — otherwise the
# seal would hide the very targets we must mask.
nonroot_outside_root() {
  [[ $CALLER_UID -ne 0 && $PWD != /root && $PWD != /root/* ]]
}
real_candidate_ok() {
  local cand=$1 resolved
  [[ -e $cand && ! -d $cand ]] || return 1
  # A non-root caller outside /root gets NS_SEAL_ROOT=1: every /root/*
  # path is sealed behind a ro empty tmpfs inside the namespace, so a
  # candidate that LIVES under /root — or whose readlink -f resolution
  # lands under /root (e.g. /usr/local/bin/herdr-core ->
  # /root/.local/bin/herdr-core) — can never be masked and must be
  # skipped here, matching the enumeration's resolved-path skip and
  # ns-hc-gotest.sh's host_hc_candidate_ok.
  if nonroot_outside_root; then
    [[ $cand != /root && $cand != /root/* ]] || return 1
    resolved=$(readlink -f "$cand" 2>/dev/null || true)
    if [[ -n $resolved ]]; then
      [[ $resolved != /root && $resolved != /root/* ]] || return 1
    fi
  fi
  return 0
}
if [[ -z $REAL_HC ]]; then
  for cand in /root/.local/bin/herdr-core /usr/local/bin/herdr-core; do
    if real_candidate_ok "$cand"; then
      REAL_HC=$cand
      break
    fi
  done
fi
[[ -n $REAL_HC ]] || die "no host hc target found (pass --real; probed /root/.local/bin, /usr/local/bin)"
[[ -e $REAL_HC ]] || die "host hc target not found: $REAL_HC"
REAL_HC=$(readlink -f "$REAL_HC") || die "cannot resolve $REAL_HC"
[[ -f $REAL_HC ]] || die "host hc target is not a regular file: $REAL_HC"
STANDIN=$(readlink -f "$STANDIN") || die "cannot resolve $STANDIN"

NS_SEAL_ROOT=0
if [[ $CALLER_UID -ne 0 && $PWD != /root && $PWD != /root/* \
      && $REAL_HC != /root && $REAL_HC != /root/* \
      && $STANDIN != /root && $STANDIN != /root/* ]]; then
  NS_SEAL_ROOT=1
fi
export NS_SEAL_ROOT

# The stand-in is bind-mounted over trusted executable slots: it must be
# executable and must stay a TRUSTED file for the payload's own trust
# checks (statUIDAndPermOK: st_uid == 0 or euid, and no 0022 group/other
# write bits). For a non-root caller under /tmp the stand-in is handed
# back to the CALLER (uid:gid), never world-writable: 0755 under a
# 1777 /tmp would let ANY local user rewrite the file between enumeration
# and masking, and a 0777 mode would trip the 0022 check the moment the
# masked path shadows a user-slot like ~/.local/bin/herdr-core.
# Mode 0755 still proves the read-only bind the gate asserts: the payload
# runs AS the caller, so its O_WRONLY passes the owner 0200 DAC check
# and then hits the ro mount for EROFS — a root-owned 0755 would instead
# fail DAC first with EACCES and could not tell ro-bind from perms.
if [[ $CALLER_UID -ne 0 && $STANDIN == /tmp/* ]]; then
  chown "$CALLER_UID:$CALLER_GID" "$STANDIN" \
    || die "cannot chown stand-in $STANDIN to caller $CALLER_UID:$CALLER_GID"
fi
chmod 0755 "$STANDIN" || die "cannot chmod stand-in $STANDIN"

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
# unmasked). Every line is masked inside the namespace. Plain synchronous
# command substitution — NOT `< <(enumerate_targets)` process
# substitution — so a die() inside enumerate_targets propagates as this
# command's non-zero status and aborts the script via `|| exit` BEFORE
# unshare is ever reached (process substitution would run the function in
# an async subshell whose failure mapfile never sees).
raw_targets=$(enumerate_targets) || exit $?
NS_TARGET_LIST=()
if [[ -n $raw_targets ]]; then
  mapfile -t NS_TARGET_LIST <<< "$raw_targets"
fi
((${#NS_TARGET_LIST[@]} > 0)) || die "no hc/herdr-core/sbx targets enumerated on host PATH/trusted dirs"
# The --real resolution must be in the set (it always is via the trusted
# bin dirs, but keep the invariant explicit).
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
  # The stub runs as the unprivileged payload uid: hand the recording log
  # back to the caller so O_APPEND|O_WRONLY can open it.
  if [[ $CALLER_UID -ne 0 ]]; then
    chown "$CALLER_UID:$CALLER_GID" "$STUB_LOG" || die "cannot chown stub log $STUB_LOG"
    chmod 0600 "$STUB_LOG" || die "cannot chmod stub log $STUB_LOG"
  fi
  export HC_STUB_LOG=$STUB_LOG
fi

note "host hc $REAL_HC dev:ino=$host_devid sha256=$host_sha"
note "stand-in  $STANDIN dev:ino=$standin_devid sha256=$standin_sha"
[[ $NS_SEAL_ROOT == 1 ]] && note "NS_SEAL_ROOT=1: /root will be sealed with a ro empty tmpfs"

export NS_STANDIN=$STANDIN NS_HOST_NS=$host_ns
export NS_HOST_DEVID=$host_devid NS_HOST_SHA=$host_sha
export NS_STANDIN_DEVID=$standin_devid NS_STANDIN_SHA=$standin_sha
export NS_TARGETS NS_CALLER_UID=$CALLER_UID NS_CALLER_GID=$CALLER_GID

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
