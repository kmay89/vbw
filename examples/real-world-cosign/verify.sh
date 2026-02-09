#!/bin/bash
set -euo pipefail

echo "═══════════════════════════════════════════════"
echo "VBW Real-World Demo: Verifying Cosign Release"
echo "═══════════════════════════════════════════════"
echo ""

echo "Checking prerequisites..."

VBW_BIN="${VBW_BIN:-vbw}"
if ! command -v "$VBW_BIN" >/dev/null 2>&1; then
  if [ -f "../../target/release/vbw" ]; then
    VBW_BIN="../../target/release/vbw"
    echo "✓ Using vbw from: $VBW_BIN"
  else
    echo "ERROR: vbw not found. Build from repo root with: cargo build --release"
    exit 1
  fi
fi

missing=()
for tool in slsa-verifier cosign in-toto-verify; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done

if [ ${#missing[@]} -gt 0 ]; then
  echo "⚠ Missing tools: ${missing[*]}"
  echo "Install:"
  echo "  slsa-verifier: go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest"
  echo "  cosign:        go install github.com/sigstore/cosign/v2/cmd/cosign@latest"
  echo "  in-toto:       pip install in-toto"
  echo ""
  read -r -p "Continue anyway? (verification may fail) [y/N] " response
  [[ "$response" =~ ^[Yy]$ ]] || exit 1
fi

echo "✓ Prerequisites OK"
echo ""

if [ ! -d "bundle" ]; then
  echo "ERROR: bundle/ not found. Run ./setup-bundle.sh first."
  exit 1
fi

if [ ! -f "bundle/keys/functionary.pub" ]; then
  echo "ERROR: bundle/keys/functionary.pub not found. Run ./setup-bundle.sh first."
  exit 1
fi

echo "Running VBW verification with in-toto cryptographic verification..."
echo ""

"$VBW_BIN" verify bundle/ \
  --artifact bundle/artifacts/cosign-linux-amd64 \
  --source-uri github.com/sigstore/cosign \
  --slsa-mode schema-only \
  --policy bundle/vbw-policy.json \
  --intoto-layout-keys bundle/keys/functionary.pub

rc=$?

echo ""
echo "═══════════════════════════════════════════════"
if [ $rc -eq 0 ]; then
  echo "✓ Verification PASSED"
  echo ""
  echo "This proves:"
  echo "  1. SLSA provenance is valid (schema-only in this demo)"
  echo "  2. in-toto root layout signature is verified (via --intoto-layout-keys)"
  echo "  3. in-toto link signatures are verified"
  echo "  4. Independence requirements are met"
  echo "  5. VBW attestation is signed and verifiable via Sigstore"
else
  echo "✗ Verification FAILED"
  echo "Check: cat bundle/vbw/report.json"
fi

echo ""
echo "Inspect the results:"
echo "  - VBW attestation: bundle/vbw/vbw-attestation.json"
echo "  - Sigstore bundle:  bundle/vbw/vbw-attestation.sigstore.bundle"
echo "  - Full report:      bundle/vbw/report.json"
echo ""
echo "View attestation with:"
echo "  $VBW_BIN show --attestation bundle/vbw/vbw-attestation.json --sigstore-bundle bundle/vbw/vbw-attestation.sigstore.bundle"
echo "═══════════════════════════════════════════════"

exit $rc
