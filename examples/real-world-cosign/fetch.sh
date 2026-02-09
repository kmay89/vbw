#!/bin/bash
set -euo pipefail

# Fetch a specific cosign release with published attestations
VERSION="v2.2.3"  # pick a known release tag
RELEASE_URL="https://github.com/sigstore/cosign/releases/download/${VERSION}"

# Defensive: ensure VERSION stays a simple tag.
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: Invalid VERSION format: $VERSION"
  exit 1
fi

echo "Fetching cosign ${VERSION} release artifacts..."

mkdir -p downloads
cd downloads

# Binary
curl -fsSL "${RELEASE_URL}/cosign-linux-amd64" -o cosign-linux-amd64
chmod +x cosign-linux-amd64

# SLSA provenance (published as DSSE envelope JSONL)
curl -fsSL "${RELEASE_URL}/attestation.intoto.jsonl" -o attestation.intoto.jsonl

echo "Extracting provenance from DSSE envelope..."

if ! command -v jq &> /dev/null; then
  echo "ERROR: jq is required. Install with: apt-get install jq (Debian/Ubuntu) or brew install jq (macOS)"
  exit 1
fi

# Extract the payload field and base64-decode it to get the in-toto Statement.
# Note: This is a demo convenience. Real verification should prefer tooling that
# validates the DSSE envelope signatures too.
jq -r '.payload' attestation.intoto.jsonl | python3 - <<'PY' > provenance.json
import sys,base64
data=sys.stdin.read().strip().encode('utf-8')
sys.stdout.buffer.write(base64.b64decode(data))
PY

} > provenance.json

echo "✓ Downloaded cosign binary ($( (stat -f%z cosign-linux-amd64 2>/dev/null || stat -c%s cosign-linux-amd64) ) bytes)"
echo "✓ Extracted SLSA provenance to downloads/provenance.json"
