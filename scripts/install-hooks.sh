#!/usr/bin/env bash
# Install git hooks from githooks/ into the repository's .git/hooks directory.
# Rejects installation if core.hooksPath is set to an external or global path
# outside .git/hooks, or if any target is a symlink, to prevent accidental
# overwrites of global/external hooks.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)

if [ ! -d "$repo_root/githooks" ]; then
  echo "❌ no githooks/ directory next to this script (expected $repo_root/githooks)." >&2
  exit 1
fi

# Drop a trailing slash, "/." and repeated slashes so ".git/hooks/",
# ".git/hooks/." and ".git/hooks//" compare as the same path. A later
# component (".git/hooks/extra") is left intact.
normalize_hooks_path() {
  local p="$1"
  while true; do
    case "$p" in
      */) p=${p%/} ;;
      */.) p=${p%/.} ;;
      *) break ;;
    esac
  done
  printf '%s\n' "$p"
}

# Physical path of an existing directory. realpath/readlink -f resolve
# symlinks; pwd -P is the fallback when neither is available.
physical_dir() {
  local d="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$d"
  elif command -v readlink >/dev/null 2>&1; then
    readlink -f "$d"
  else
    (cd "$d" && pwd -P)
  fi
}

expected_hooks_dir="$repo_root/.git/hooks"

hooks_path=$(git -C "$repo_root" config core.hooksPath || true)
if [ -n "$hooks_path" ]; then
  hooks_path=$(normalize_hooks_path "$hooks_path")
  case "$hooks_path" in
    /*) hooks_dir=$hooks_path ;;
    *) hooks_dir="$repo_root/$hooks_path" ;;
  esac
  if [ ! -d "$hooks_dir" ]; then
    echo "❌ core.hooksPath is set to '$hooks_path' but '$hooks_dir' does not exist; aborting." >&2
    exit 1
  fi
  # Verify target hooks directory is within repository .git/hooks. Compare
  # physical paths so a symlink (and a trailing-slash spelling of one) cannot
  # compare equal to the repository directory.
  canonical_hooks_dir=$(physical_dir "$hooks_dir")
  canonical_expected=$(physical_dir "$expected_hooks_dir")
  if [ "$canonical_hooks_dir" != "$canonical_expected" ] && [[ "$canonical_hooks_dir" != "$canonical_expected"/* ]]; then
    echo "❌ refusing to install: target hooks directory '$hooks_dir' ($canonical_hooks_dir) is outside repository .git/hooks ($canonical_expected)." >&2
    echo "   core.hooksPath is set to an external/global path. Aborting to protect external hooks." >&2
    exit 1
  fi
else
  hooks_dir="$expected_hooks_dir"
  if [ ! -d "$hooks_dir" ]; then
    echo "❌ no hooks directory at $hooks_dir (run inside a git work tree)." >&2
    exit 1
  fi
fi

# Reject if the hooks directory itself is a symlink. Check the undecorated
# repository path: a trailing "/" or "/." on core.hooksPath makes [ -L ] false
# even when .git/hooks is the symlink.
if [ -L "$hooks_dir" ] || [ -L "$expected_hooks_dir" ]; then
  echo "❌ refusing to install: hooks directory '$hooks_dir' is a symlink; aborting." >&2
  exit 1
fi

# Re-resolve the destination immediately before copying and refuse anything
# that is no longer the repository .git/hooks directory.
canonical_hooks_dir=$(physical_dir "$hooks_dir")
canonical_expected=$(physical_dir "$expected_hooks_dir")
if [ "$canonical_hooks_dir" != "$canonical_expected" ]; then
  echo "❌ refusing to install: resolved hooks directory '$canonical_hooks_dir' is not repository .git/hooks ($canonical_expected)." >&2
  exit 1
fi

# Copy without following a symlink. Remove the destination first (the link
# itself when it is a symlink): cp -P still follows a symlink that is the
# destination and would overwrite the file it points at outside the repository.
for hook in "$repo_root"/githooks/*; do
  [ -f "$hook" ] || continue
  name=$(basename "$hook")
  target="$hooks_dir/$name"
  if [ -e "$target" ] && [ ! -L "$target" ] && [ ! -f "$target" ]; then
    echo "❌ refusing to install: target hook '$target' is not a regular file." >&2
    exit 1
  fi
  rm -f "$target"
  cp -P "$hook" "$target"
  chmod +x "$target"
done

echo "✅ Git hooks installed into $hooks_dir: $(ls "$repo_root"/githooks/ | tr '\n' ' ')"
