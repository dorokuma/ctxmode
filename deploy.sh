#!/bin/bash
# ctxmode 一键部署：编译 → 原子替换二进制
# 用法: deploy.sh [deploy]    编译并原子部署（默认）
#       deploy.sh rollback    回滚到上一次部署前的二进制（${BINARY}.prev）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BINARY="${BINARY:-$HOME/.local/bin/ctxmode}"
BUILD_OUT="$ROOT/bin/ctxmode"

case "${1:-deploy}" in
  deploy|rollback) ;;
  *)
    echo "用法: $0 [deploy|rollback]" >&2
    exit 1
    ;;
esac

# ===== rollback fragment: start =====
# deploy.sh rollback：把上一次部署前的二进制（${BINARY}.prev）原子换回。
# 与 deploy 相同的铁律：先 initialize 验证，验证通过才替换；任何失败都
# 保持现状并以 1 退出。回滚成功会消耗 .prev（mv）；再次 deploy 会重新生成备份。
if [ "${1:-}" = "rollback" ]; then
  PREV="${BINARY}.prev"
  TARGET_DIR="$(dirname "$BINARY")"
  if [ ! -f "$PREV" ]; then
    echo "rollback 失败: 备份不存在 (${PREV})，无从回滚" >&2
    exit 1
  fi
  if ! command -v timeout >/dev/null 2>&1; then
    echo "需要 coreutils timeout 才能验证备份二进制" >&2
    exit 1
  fi
  echo "=== 验证备份二进制 ==="
  ROLL_ERR="$(mktemp "$TARGET_DIR/.ctxmode.XXXXXX")"
  cleanup_roll_err() {
    rm -f -- "$ROLL_ERR"
  }
  trap cleanup_roll_err EXIT
  # stdin EOF 竞态：与 deploy 相同，失败重试 3 次。
  VERIFY=""
  VERIFY_RC=1
  # 验证失败是预期分支，先关 set -e（与 deploy fragment 相同），循环后再恢复。
  set +e
  for attempt in 1 2 3; do
    VERIFY=$( (echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"deploy-check","version":"1"}}}'; sleep 1) | timeout 5 "$PREV" 2>"$ROLL_ERR" )
    VERIFY_RC=$?
    if [ "$VERIFY_RC" -eq 0 ] && printf '%s' "$VERIFY" | grep -qE '"version"[[:space:]]*:[[:space:]]*"[^"]+"'; then
      break
    fi
    [ "$attempt" -eq 3 ] || sleep 1
  done
  set -e
  if [ "$VERIFY_RC" -ne 0 ] || ! printf '%s' "$VERIFY" | grep -qE '"version"[[:space:]]*:[[:space:]]*"[^"]+"'; then
    echo "备份二进制 initialize 验证失败 (exit ${VERIFY_RC})，保持现状不回滚" >&2
    if [ -s "$ROLL_ERR" ]; then
      echo "initialize stderr:" >&2
      cat -- "$ROLL_ERR" >&2
    fi
    exit 1
  fi
  VERSION="$(printf '%s' "$VERIFY" | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | cut -d'"' -f4)"
  if [ -z "$VERSION" ]; then
    echo "备份二进制 initialize 响应里没有版本号，保持现状不回滚" >&2
    exit 1
  fi
  rm -f -- "$ROLL_ERR"
  # PREV 与 BINARY 同目录：mv 是同文件系统 rename，原子生效。
  mv -f -- "$PREV" "$BINARY"
  echo "ctxmode v${VERSION} 回滚成功 → ${BINARY}"
  echo "提示: .prev 已被消耗；再次 deploy.sh 会重新部署并生成新备份"
  exit 0
fi
# ===== rollback fragment: end =====

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
# stdin EOF 竞态：新二进制偶发在关闭流程中收到 EOF 以 rc=1 退出
# （"server is closing: EOF"），与被验证二进制本身无关，重试即可。
trap - ERR
set +e
VERIFY=""
VERIFY_RC=1
for attempt in 1 2 3; do
  VERIFY=$( (echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"deploy-check","version":"1"}}}'; sleep 1) | timeout 5 "$TMP_FILE" 2>"$TMP_FILE.err" )
  VERIFY_RC=$?
  if [ "$VERIFY_RC" -eq 0 ] && printf '%s' "$VERIFY" | grep -qE '"version"[[:space:]]*:[[:space:]]*"[^"]+"'; then
    break
  fi
  [ "$attempt" -eq 3 ] || sleep 1
done
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
# 替换前备份当前线上二进制，供 deploy.sh rollback 原子换回。
# 失败容忍：备份失败只告警不阻断部署（没有备份时 rollback 会明确报错）。
if [ -f "$BINARY" ]; then
  cp -- "$BINARY" "${BINARY}.prev" || echo "警告: 备份当前二进制失败，本次部署后 rollback 不可用" >&2
fi
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

echo "=== Pi extension ==="
EXT_SRC="$ROOT/integrations/pi/ctxmode.ts"
EXT_DST="${PI_CTXMODE_EXT:-$HOME/.pi/agent/extensions/ctxmode.ts}"
if [ ! -f "$EXT_SRC" ]; then
  echo "missing Pi extension $EXT_SRC" >&2
  exit 1
fi
mkdir -p -- "$(dirname "$EXT_DST")"
install -m 644 "$EXT_SRC" "$EXT_DST"
echo "Pi extension → $EXT_DST"

echo "=== 完成 ==="
echo "Pi 无 MCP：工具来自扩展。在 Pi 里 /reload 重载扩展（会再 spawn 新二进制）。"
