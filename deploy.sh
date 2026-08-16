#!/bin/bash
# ctxmode 一键部署：编译 → 原子替换二进制
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BINARY="${BINARY:-$HOME/.local/bin/ctxmode}"
BUILD_OUT="$ROOT/bin/ctxmode"

echo "=== 编译 ==="
cd "$ROOT"
mkdir -p bin
go build -o "$BUILD_OUT" . 2>&1
echo "编译完成 ($(du -h "$BUILD_OUT" | cut -f1))"

echo "=== 原子部署 ==="
# ===== atomic deploy fragment: start =====
# 临时文件建在目标目录内（同文件系统，mv 才是原子替换）。
# 先对即将就位的临时文件做 initialize；通过后再 mv。
# 验证失败则清理临时文件并非 0 退出，旧目标保持不动。
# 失败时 ERR trap 也会清理临时文件；成功替换后解除 trap。
TARGET_DIR="$(dirname "$BINARY")"
mkdir -p -- "$TARGET_DIR"

TMP_FILE=""
cleanup_tmp() {
  if [ -n "$TMP_FILE" ]; then
    rm -f -- "$TMP_FILE" "$TMP_FILE.err"
  fi
}
trap cleanup_tmp ERR

TMP_FILE="$(mktemp "$TARGET_DIR/.ctxmode.XXXXXX")"
install -m 755 "$BUILD_OUT" "$TMP_FILE"

if ! command -v timeout >/dev/null 2>&1; then
  echo "需要 coreutils timeout 才能验证新二进制" >&2
  cleanup_tmp
  exit 1
fi

# 验证即将就位的文件，不要先换再验。
# 不用 2>/dev/null：失败时把 initialize 的 stderr/stdout 打出来。
# 验证失败是预期分支，必须先拆掉 ERR trap，否则 trap 会先删掉 .err，
# 失败原因就看不到了。
trap - ERR
set +e
VERIFY=$( (echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"deploy-check","version":"1"}}}'; sleep 1) | timeout 5 "$TMP_FILE" 2>"$TMP_FILE.err" )
VERIFY_RC=$?
set -e
if [ "$VERIFY_RC" -ne 0 ] || ! printf '%s' "$VERIFY" | grep -qE '"version"[[:space:]]*:[[:space:]]*"[^"]+"'; then
  echo "新二进制 initialize 验证失败 (exit ${VERIFY_RC})" >&2
  if [ -s "$TMP_FILE.err" ]; then
    echo "initialize stderr:" >&2
    cat -- "$TMP_FILE.err" >&2
  fi
  if [ -n "$VERIFY" ]; then
    echo "initialize stdout:" >&2
    printf '%s\n' "$VERIFY" >&2
  fi
  cleanup_tmp
  exit 1
fi
VERSION=$(printf '%s' "$VERIFY" | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | cut -d'"' -f4)
if [ -z "$VERSION" ]; then
  echo "initialize 响应里没有版本号" >&2
  cleanup_tmp
  exit 1
fi
rm -f -- "$TMP_FILE.err"

trap cleanup_tmp ERR
mv -f -- "$TMP_FILE" "$BINARY"
trap - ERR
# ===== atomic deploy fragment: end =====
echo "部署完成 → $BINARY"
rm -rf "$ROOT/bin"
echo "已清理编译产物 $ROOT/bin"

if [ -z "${VERSION:-}" ]; then
  echo "验证未产生版本号，拒绝报告成功" >&2
  exit 1
fi
echo "ctxmode v${VERSION} 部署成功"

echo "=== 完成 ==="
echo "在 pi 里敲 /reload 让扩展重新扫码新的二进制。"
