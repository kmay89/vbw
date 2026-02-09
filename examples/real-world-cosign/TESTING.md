# Testing in-toto cryptographic verification

These tests prove the demo is doing **real signature verification**.

## 1) Happy path

```bash
./fetch.sh
./setup-bundle.sh
./verify.sh
```

You should see `✓ in-toto ok`.

## 2) Tamper with a signed link

```bash
echo "TAMPERED" >> bundle/links/build.*.link
./verify.sh
```

Expected: `✗ in-toto failed` (signature verification failure).

## 3) Omit verification keys

From the repo root:

```bash
./target/release/vbw verify examples/real-world-cosign/bundle \
  --artifact examples/real-world-cosign/bundle/artifacts/cosign-linux-amd64 \
  --slsa-mode schema-only
```

Expected: in-toto runs in **structural-only** mode (no signature checking).
