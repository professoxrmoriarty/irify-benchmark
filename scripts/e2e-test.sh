#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

echo "=== Building irify-benchmark ==="
cd "${ROOT_DIR}"
go build -o "${BUILD_DIR}/irify-benchmark" ./cmd/irify-benchmark

echo "=== Running E2E test: java-cmdi-001 ==="
TEST_CASE="${ROOT_DIR}/cases/java-cmdi-001"
TEST_OUT="${BUILD_DIR}/e2e-output"
mkdir -p "${TEST_OUT}"

# Step 1: Scan with mock engine (since yaklang may not be available in test env)
# For E2E, we'll use a mock finding to test the full pipeline
# Create a mock finding that should match the case
cat > "${TEST_OUT}/findings.json" <<'EOF'
{
  "engine": "mock",
  "engine_version": "1.0.0",
  "scan_time": "2026-05-21T15:00:00Z",
  "program_name": "java-cmdi-001",
  "findings": [
    {
      "rule_id": "java-cmdi-001",
      "rule_name": "Command Injection",
      "severity": "high",
      "confidence": "high",
      "flow": {
        "source": {"symbol": "request.getParameter", "line": 13, "column": 20, "file": "Hello.java"},
        "sanitizers": [],
        "sink": {"symbol": "Runtime.getRuntime().exec", "line": 15, "column": 8, "file": "Hello.java"}
      }
    }
  ]
}
EOF

# Step 2: Run match
"${BUILD_DIR}/irify-benchmark" match \
  --annotation "${TEST_CASE}/annotation.json" \
  --findings "${TEST_OUT}/findings.json" \
  --output "${TEST_OUT}/result.json"

# Step 3: Verify result
echo "=== Verifying result ==="
TP=$(cat "${TEST_OUT}/result.json" | grep -o '"tp":[[:space:]]*[0-9]*' | grep -o '[0-9]*' || true)
FN=$(cat "${TEST_OUT}/result.json" | grep -o '"fn":[[:space:]]*[0-9]*' | grep -o '[0-9]*' || true)

# If fn is missing due to omitempty, it means 0.
if [ "${TP}" = "" ]; then TP="0"; fi
if [ "${FN}" = "" ]; then FN="0"; fi

echo "TP: ${TP}, FN: ${FN}"

if [ "${TP}" != "1" ]; then
    echo "FAIL: Expected TP=1, got TP=${TP}"
    exit 1
fi

if [ "${FN}" != "0" ]; then
    echo "FAIL: Expected FN=0, got FN=${FN}"
    exit 1
fi

echo "=== E2E test PASSED ==="
