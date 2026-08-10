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
mkdir -p "$(dirname "$BINARY")"
install -m 755 "$BUILD_OUT" "$BINARY"
echo "部署完成 → $BINARY"
rm -rf "$ROOT/bin"
echo "已清理编译产物 $ROOT/bin"

echo "=== 验证 ==="
VERIFY=$( (echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"deploy-check","version":"1"}}}'; sleep 1) | timeout 5 "$BINARY" 2>/dev/null)
VERSION=$(echo "$VERIFY" | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "ctxmode v${VERSION:-?} 部署成功"

echo "=== 完成 ==="
echo "在 pi 里敲 /reload 让扩展重新扫码新的二进制。"
