#!/bin/bash
set -euo pipefail

KEY_NAME="${1:-functionary}"

if ! command -v in-toto-keygen >/dev/null 2>&1; then
  echo "ERROR: in-toto-keygen not found"
  echo "Install: pip install in-toto"
  exit 1
fi

echo "Generating in-toto keypair: $KEY_NAME"
in-toto-keygen "$KEY_NAME"

echo ""
echo "✓ Generated:"
echo "  - Private key: $KEY_NAME"
echo "  - Public key:  $KEY_NAME.pub"
echo ""
echo "⚠ IMPORTANT: keep the private key secure."