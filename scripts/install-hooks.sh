#!/usr/bin/env bash
# Install git hooks from githooks/ into the effective hooks directory.
# Honors core.hooksPath when set (relative paths resolve against the repo
# root); otherwise installs into .git/hooks. Fails fast if the target
# hooks directory does not exist — never claims to have installed into
# a directory that would not actually be used.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)

if [ ! -d "$repo_root/githooks" ]; then
  echo "❌ no githooks/ directory next to this script (expected $repo_root/githooks)." >&2
  exit 1
fi

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
else
  hooks_dir="$repo_root/.git/hooks"
  if [ ! -d "$hooks_dir" ]; then
    echo "❌ no hooks directory at $hooks_dir (run inside a git work tree)." >&2
    exit 1
  fi
fi

for hook in "$repo_root"/githooks/*; do
  [ -f "$hook" ] || continue
  name=$(basename "$hook")
  cp "$hook" "$hooks_dir/$name"
  chmod +x "$hooks_dir/$name"
done

echo "✅ Git hooks installed into $hooks_dir: $(ls "$repo_root"/githooks/ | tr '\n' ' ')"
