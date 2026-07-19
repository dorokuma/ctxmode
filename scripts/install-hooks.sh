#!/usr/bin/env bash
# Install git hooks from githooks/ into .git/hooks/
set -euo pipefail
cd "$(dirname "$0")"
for hook in githooks/*; do
  name=$(basename "$hook")
  cp "$hook" ".git/hooks/$name"
  chmod +x ".git/hooks/$name"
done
echo "✅ Git hooks installed: $(ls githooks/ | tr '\n' ' ')"
