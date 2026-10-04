#!/usr/bin/env bash
# install.sh — 把仓库版 Pi 扩展同步安装到 ~/.pi/agent/extensions/。
#
# 背景：deploy.sh 除了部署 Go 二进制，还负责同步 Pi 扩展
# （integrations/pi/ctxmode.ts）。此前该步骤是 deploy.sh 里的内联块：
# 无条件 install 重写（md5 一致也动 mtime）、无 md5sum 预检、无 HOME /
# 目标形态校验，失败形态不可见。本脚本把该步骤提炼出来，契约与
# codegraph-go 的 integrations/pi/install.sh 对齐（样板：
# /root/workspace/codegraph-go/integrations/pi/install.sh），部署时由
# deploy.sh 调用，也可单独执行验证：
#   integrations/pi/install.sh
#
# DEST 语义定稿：目标是一个「文件路径」（~/.pi/agent/extensions/
# ctxmode.ts），不接受目录——指向已存在目录时显式失败，不静默补全
# 文件名、不静默拷进目录。PI_CTXMODE_EXT 可覆盖（沿用 deploy.sh 既有
# 的覆盖变量名与默认路径语义，既有调用方式不变）。
#
# 幂等：目标 md5 与源一致时报告未变化且不重写（不动 mtime）。
# 失败语义：所有校验/IO 失败都必须有可见输出（stderr）并非零退出——
# 静默失败是本次要消灭的形态（原内联块缺源只 exit 1、缺 md5sum 则连
# command not found 都看不到）。
set -euo pipefail

fail() { echo "install.sh FAILED: $*" >&2; exit 1; }

# md5sum 缺失必须显式失败：若把 command not found 吞掉，表现为零输出 +
# 静默退出，同步失败却无任何信号。
command -v md5sum >/dev/null 2>&1 || fail "md5sum not found in PATH (PATH=$PATH)"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$ROOT/integrations/pi/ctxmode.ts"

# 目标解析顺序：优先采纳显式覆盖 PI_CTXMODE_EXT，仅在未指定时才校验 HOME、
# 回落到默认路径。修前顺序倒挂（先校验 HOME 再取 PI_CTXMODE_EXT），导致显式设了
# PI_CTXMODE_EXT 也照样被「HOME is not set」拦下，而报错文案偏又教用户「set
# PI_CTXMODE_EXT explicitly」——文案与行为自相矛盾（审读实测：env -u HOME
# PI_CTXMODE_EXT=/tmp/ext.ts bash install.sh 修复前 FAILED、exit 1）。口径与
# codegraph-go 等其余副本一致。
if [ -n "${PI_CTXMODE_EXT:-}" ]; then
  DEST="$PI_CTXMODE_EXT"
else
  # HOME 未导出时 set -u 只会抛一句晦涩的「未绑定的变量」；显式给出可操作提示。
  HOME_DIR="${HOME:-}"
  [ -n "$HOME_DIR" ] || fail "HOME is not set (or empty) — export HOME or set PI_CTXMODE_EXT explicitly"
  DEST="$HOME_DIR/.pi/agent/extensions/ctxmode.ts"
fi
[ -n "$DEST" ] || fail "destination is empty"
case "$DEST" in
  /*) ;;
  *) fail "destination is not an absolute path: $DEST" ;;
esac
if [ -d "$DEST" ]; then
  fail "destination is a directory: $DEST — expected the extension file path (须指定文件名而非目录本体)"
fi

[ -f "$SRC" ] || fail "source not found: $SRC"

md5_of() {
  local line
  # 不吞 stderr、不吞退出码：md5sum 本身的失败（如文件不可读）也要显性化。
  if ! line="$(md5sum "$1")"; then
    fail "md5sum failed for: $1"
  fi
  printf '%s' "${line%% *}"
}

SRC_MD5="$(md5_of "$SRC")"
[ -n "$SRC_MD5" ] || fail "source md5 is empty: $SRC"
if [ -f "$DEST" ]; then
  DEST_MD5="$(md5_of "$DEST")"
  [ -n "$DEST_MD5" ] || fail "target md5 is empty: $DEST"
else
  DEST_MD5="(none)"
fi

echo "pi extension sync"
echo "  source:      $SRC"
echo "  source md5:  $SRC_MD5"
echo "  destination: $DEST"
echo "  target md5:  $DEST_MD5"

if [ -f "$DEST" ] && [ "$DEST_MD5" = "$SRC_MD5" ]; then
  echo "unchanged: destination already matches source (md5 $SRC_MD5), nothing written"
else
  # 目标父目录在新机器上可能不存在（~/.pi/agent/extensions），先建好。
  mkdir -p "$(dirname "$DEST")"
  install -m 644 "$SRC" "$DEST"
  echo "changed: installed $DEST (md5 $SRC_MD5)"
fi

echo "note: Pi 只在会话启动时加载扩展——需 /reload 或新会话才生效"
