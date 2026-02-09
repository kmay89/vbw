# Real-world demo: verifying a Cosign release

This example verifies a published **Cosign** GitHub release with:

* **SLSA provenance** (decoded from Cosign’s DSSE `attestation.intoto.jsonl`)
* **in-toto cryptographic verification** (signed root layout + signed link)
* **VBW independence checks** (no secrets, no private network refs, etc.)
* **VBW meta-attestation**, signed with **Sigstore cosign**

## Prerequisites

```bash
# VBW (from repo root)
cargo build --release

# Tools used by the demo
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
pip install in-toto
```

You’ll also need `jq`.

## Quick start

```bash
./fetch.sh
./setup-bundle.sh
./verify.sh
```

## What “cryptographic in-toto verification” means here

`setup-bundle.sh` generates a demo functionary key and then:

1. Creates an **unsigned** `layout.json` that authorizes that key.
2. Uses `in-toto-sign` to produce a **signed root layout**.
3. Uses `in-toto-run` to produce a **signed link** for the “build” step.

Then `vbw verify ... --intoto-layout-keys bundle/keys/functionary.pub` runs `in-toto-verify` to validate those signatures.

If you tamper with the link file, verification fails (see `TESTING.md`).