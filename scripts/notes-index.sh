#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NOTES_DIR="${REPO_ROOT}/.agents/notes"
INDEX_FILE="${NOTES_DIR}/INDEX.md"

mkdir -p "${NOTES_DIR}"

# 收集笔记文件列表（排除 _template.md, README.md, INDEX.md）
files=()
while IFS= read -r file; do
    [[ -n "$file" ]] && files+=("$file")
done < <(find "${NOTES_DIR}" -maxdepth 1 -name "*.md" ! -name "_template.md" ! -name "README.md" ! -name "INDEX.md" -exec basename {} \; | sort -r)

count=${#files[@]}

{
    echo "# 决策与架构笔记索引"
    echo ""
    echo "<!-- 本文件由 scripts/notes-index.sh 自动生成，请勿手动编辑 -->"
    echo ""
    if [ "$count" -eq 0 ]; then
        echo "暂无笔记。"
    else
        echo "| 日期 | 模块 | 状态 | 标题 |"
        echo "| --- | --- | --- | --- |"
        for f in "${files[@]}"; do
            note_path="${NOTES_DIR}/${f}"

            # 提取日期（从文件名 YYYYMMDD 或 YYYY-MM-DD，若无则使用文件修改日期）
            if [[ "$f" =~ ^([0-9]{4})-?([0-9]{2})-?([0-9]{2}) ]]; then
                date="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]}"
            else
                date=$(date -r "${note_path}" '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')
            fi

            # 从 frontmatter 提取模块与状态
            module=$(awk -F: '/^[[:space:]]*(模块|module):/ { sub(/^[[:space:]]*(模块|module):[[:space:]]*/, ""); sub(/[[:space:]]*#.*/, ""); gsub(/["'\'']/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }' "${note_path}" || true)
            status=$(awk -F: '/^[[:space:]]*status:/ { sub(/^[[:space:]]*status:[[:space:]]*/, ""); sub(/[[:space:]]*#.*/, ""); gsub(/["'\'']/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit }' "${note_path}" || true)

            module="${module:-"-"}"
            status="${status:-"-"}"

            # 提取一级标题
            title=$(grep -m 1 -E '^# ' "${note_path}" | sed -E 's/^#[[:space:]]*//; s/^[[:space:]]*//; s/[[:space:]]*$//' || true)
            if [ -z "$title" ]; then
                title="$f"
            fi

            # 转义管道符防止破坏表格格式
            title="${title//|/\\|}"

            echo "| ${date} | ${module} | ${status} | [${title}](${f}) |"
        done
    fi
} > "${INDEX_FILE}"

echo "笔记索引已更新，笔记总数: $count"
