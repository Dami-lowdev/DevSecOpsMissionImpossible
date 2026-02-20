#!/bin/sh
set -eu

echo "[CI] Running intentionally weak pipeline..."
echo "[CI] 1) Lint? (skipped)"
echo "[CI] 2) Tests? (skipped)"
echo "[CI] 3) Dependency audit? (skipped)"
echo "[CI] 4) Build image with latest tag (bad)"
docker build -t mycorp/escape-app:latest .

echo "[CI] 5) Image scan? (skipped)"
echo "[CI] 6) SBOM? (skipped)"
echo "[CI] 7) Signing? (skipped)"

echo "[CI] Done (insecure). Your job: harden this pipeline."
