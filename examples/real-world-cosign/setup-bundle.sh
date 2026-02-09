#!/bin/bash
set -euo pipefail

echo "Setting up VBW verification bundle with in-toto signing..."

# Tooling checks
for t in in-toto-run in-toto-verify in-toto-sign in-toto-keygen python3; do
  if ! command -v "$t" >/dev/null 2>&1; then
    echo "ERROR: $t not found"
    echo "Install: pip install in-toto"
    exit 1
  fi
done

# Create bundle structure
mkdir -p bundle/{links,artifacts,keys}

# Copy artifacts
if [ ! -f downloads/cosign-linux-amd64 ] || [ ! -f downloads/provenance.json ]; then
  echo "ERROR: downloads/ missing required files"
  echo "Run ./fetch.sh first"
  exit 1
fi

cp downloads/cosign-linux-amd64 bundle/artifacts/
cp downloads/provenance.json bundle/provenance.json

echo "Generating in-toto keypair for demo (functionary)..."
( cd bundle/keys && [ -f functionary ] || in-toto-keygen functionary )

# Produce functionary key metadata (keyid + public key dict) in the exact format
# in-toto expects inside layout.json under `keys`.
mapfile -t _KEY_LINES < <(python3 - <<'PY'
import json

try:
  # Newer securesystemslib versions
  from cryptography.hazmat.primitives.serialization import load_pem_public_key
  from securesystemslib.signer import SSlibKey
  pem = open('bundle/keys/functionary.pub','rb').read()
  pub = load_pem_public_key(pem)
  key = SSlibKey.from_crypto(public_key=pub)
  keyid = key.keyid
  keydict = key.to_dict()
except Exception:
  # Legacy fallback
  from securesystemslib.keys import import_rsa_publickey_from_file
  keydict = import_rsa_publickey_from_file('bundle/keys/functionary.pub')
  keyid = keydict.get('keyid')

print(keyid)
print(json.dumps(keydict))
PY)

KEYID="${_KEY_LINES[0]:-}"
KEYDICT_JSON="${_KEY_LINES[1]:-}"

if [ -z "${KEYID:-}" ] || [ -z "${KEYDICT_JSON:-}" ]; then
  echo "ERROR: failed to derive in-toto keyid/key dict"
  exit 1
fi

echo "Functionary keyid: $KEYID"

echo "Creating unsigned layout.json..."
cat > bundle/layout.unsigned.json <<EOF
{
  "_type": "layout",
  "steps": [
    {
      "name": "build",
      "expected_command": [],
      "expected_materials": [],
      "expected_products": [
        ["MATCH", "cosign-linux-amd64", "WITH", "PRODUCTS", "FROM", "build"]
      ],
      "pubkeys": ["$KEYID"],
      "threshold": 1
    }
  ],
  "inspect": [],
  "keys": {
    "$KEYID": $KEYDICT_JSON
  },
  "expires": "2030-12-31T23:59:59Z"
}
EOF

echo "Signing layout (root layout) with in-toto-sign..."
in-toto-sign \
  -f bundle/layout.unsigned.json \
  -k bundle/keys/functionary \
  -o bundle/layout.json

echo "Creating signed link metadata (build.*.link) with in-toto-run..."
( cd bundle && \
  in-toto-run \
    --step-name build \
    --signing-key keys/functionary \
    --products artifacts/cosign-linux-amd64 \
    -- echo "Build step completed" )

# Move the generated link(s) into links/
mv bundle/build.*.link bundle/links/ 2>/dev/null || true

echo "Writing VBW policy..."
cat > bundle/vbw-policy.json <<'EOF'
{
  "allowed_builder_prefixes": [
    "https://github.com/",
    "https://github.com/slsa-framework/slsa-github-generator"
  ],
  "builder_allowlist_is_warning": false,
  "forbid_private_network_refs": true,
  "forbid_secrets": true,
  "require_digests": true
}
EOF

echo "✓ Bundle structure created with cryptographic in-toto metadata"
echo ""
echo "Bundle contents:"
if command -v tree >/dev/null 2>&1; then
  tree bundle/
else
  find bundle/ -type f | sort
fi

echo ""
echo "Layout verification key: bundle/keys/functionary.pub"
echo "To verify: ./verify.sh"
