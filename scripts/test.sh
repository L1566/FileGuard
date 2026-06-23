#!/usr/bin/env bash
# FileGuard 测试脚本（含覆盖率）
# 用法: ./scripts/test.sh [package pattern]
set -euo pipefail

COVERAGE_DIR="coverage"
PATTERN="${1:-./...}"

echo "==> Running tests with coverage..."
mkdir -p "${COVERAGE_DIR}"

# 运行所有测试并生成覆盖率报告
go test -race -coverprofile="${COVERAGE_DIR}/coverage.out" \
    -covermode=atomic \
    -count=1 \
    "${PATTERN}"

# 显示覆盖率摘要
echo ""
echo "==> Coverage summary:"
go tool cover -func="${COVERAGE_DIR}/coverage.out" | tail -n 1

# 生成 HTML 报告
go tool cover -html="${COVERAGE_DIR}/coverage.out" -o "${COVERAGE_DIR}/coverage.html"
echo "   HTML report: ${COVERAGE_DIR}/coverage.html"

# 输出每个包的覆盖率
echo ""
echo "==> Per-package coverage:"
go tool cover -func="${COVERAGE_DIR}/coverage.out" | grep -v "total:" | sort
