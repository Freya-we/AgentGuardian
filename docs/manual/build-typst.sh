#!/bin/bash
# 编译技术手册: 拼接 Typst 章节 → 编译 PDF
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT="$PROJECT_ROOT/docs/technical-manual.typ"
PDF="$PROJECT_ROOT/docs/technical-manual.pdf"

echo "==> 拼接 Typst 章节..."
cat "$SCRIPT_DIR"/0*.typ > "$OUTPUT"

echo "==> 编译 PDF..."
cd "$PROJECT_ROOT/docs"
typst compile technical-manual.typ technical-manual.pdf

echo "==> 完成: $PDF"
ls -lh "$PDF"
pdfinfo "$PDF" 2>/dev/null | grep -E "Pages|Title" || true
