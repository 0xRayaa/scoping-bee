#!/usr/bin/env bash
# run_threat_scan.sh — Runs the threat intel scanner inside an isolated Docker container.
#
# Usage:
#   bash run_threat_scan.sh <target_directory>
#
# Exit codes:
#   0  = CLEAN
#   10 = MEDIUM findings (warn, ask user to confirm)
#   20 = HIGH findings (block, do not proceed)
#   1  = Docker unavailable or error — fall back to THREAT_INTEL_SKILL.md

set -uo pipefail

TARGET="${1:-.}"
IMAGE="ghcr.io/0xrayaa/scoping-bee-scanner:latest"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -d "$TARGET" ]; then
  echo "❌ Directory not found: $TARGET"
  exit 1
fi

if ! command -v docker &>/dev/null; then
  echo "❌ Docker not found."
  echo "   Install Docker, or run the manual scan via THREAT_INTEL_SKILL.md."
  exit 1
fi

# Pull from registry; build locally on first use if registry pull fails
if ! docker image inspect "$IMAGE" &>/dev/null 2>&1; then
  echo "🐝 Pulling scanner image..."
  if ! docker pull "$IMAGE" 2>/dev/null; then
    echo "⚠️  Registry pull failed — building locally (one-time setup)..."
    docker build -t "$IMAGE" -f "$REPO_ROOT/scanner/Dockerfile" "$REPO_ROOT"
  fi
fi

ABS_TARGET="$(cd "$TARGET" && pwd)"

echo "🐝 Starting isolated threat scan..."
echo "   Image:  $IMAGE"
echo "   Target: $ABS_TARGET"
echo "   Mode:   read-only mount, no network"
echo ""

EXIT_CODE=0
docker run --rm \
  --network none \
  -v "$ABS_TARGET:/scan:ro" \
  "$IMAGE" /scan || EXIT_CODE=$?

exit $EXIT_CODE
