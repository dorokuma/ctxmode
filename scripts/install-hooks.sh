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

expected_hooks_dir="$repo_root/.git/hooks"

hooks_path=$(git -C "$repo_root" config core.hooksPath || true)
if [ -n "$hooks_path" ]; then
  case "$hooks_path" in
    /*) hooks_dir=$hooks_path ;;
    *) hooks_dir="$repo_root/$hooks_path" ;;
  esac
  if [ ! -d "$hooks_dir" ]; then
    echo "❌ core.hooksPath is set to '$hooks_path' but '$hooks_dir' does not exist; aborting." >&2
    exit 1
  fi
  # Verify target hooks directory is within repository .git/hooks
  canonical_hooks_dir=$(cd "$hooks_dir" 2>/dev/null && pwd -P || realpath "$hooks_dir")
  canonical_expected=$(cd "$expected_hooks_dir" 2>/dev/null && pwd -P || realpath "$expected_hooks_dir" 2>/dev/null || echo "$expected_hooks_dir")
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

# Reject if the hooks directory itself is a symlink
if [ -L "$hooks_dir" ]; then
  echo "❌ refusing to install: hooks directory '$hooks_dir' is a symlink; aborting." >&2
  exit 1
fi

# Pre-validate that no target hook is a symlink before installing
for hook in "$repo_root"/githooks/*; do
  [ -f "$hook" ] || continue
  name=$(basename "$hook")
  target="$hooks_dir/$name"
  if [ -L "$target" ]; then
    echo "❌ refusing to install: target hook '$target' is a symlink; aborting to avoid overwriting symlink target." >&2
    exit 1
  fi
done

# Safe copy without following symlinks
for hook in "$repo_root"/githooks/*; do
  [ -f "$hook" ] || continue
  name=$(basename "$hook")
  target="$hooks_dir/$name"
  cp -P "$hook" "$target"
  chmod +x "$target"
done

echo "✅ Git hooks installed into $hooks_dir: $(ls "$repo_root"/githooks/ | tr '\n' ' ')"

