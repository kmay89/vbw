# Architecture

VBW is intentionally small.

## Inputs (provided by build owner)
- **SLSA provenance** (evidence format)
- **in-toto layout + link metadata** (supply chain workflow evidence)
- **Sigstore signatures** (keyless signing + transparency log)

## VBW processing layer
VBW runs three classes of checks:

1. **Cryptographic & workflow checks (delegated to existing tools)**
   - `slsa-verifier` for artifact/provenance verification
   - `in-toto-verify` for workflow/layout verification
   - `cosign` for signing + verification of VBW’s own output

2. **Independence enforcement (VBW value-add)**
   VBW rejects evidence that implies:
   - embedded secrets/credentials
   - private/internal network references
   - missing digests (non-reproducible evidence)
   - builder identity outside policy allowlist (warning or failure per policy)

3. **Attestation output**
   VBW emits an **in-toto Statement v1** with a VBW predicate and a hash of the input evidence bundle.

## Threat model boundary
VBW does **not** claim to prove:
- that the source code is correct
- that the builder is honest
- that the build is secure

VBW **does** claim to prove:
- the submitted evidence is internally consistent and policy-compliant
- the VBW attestation is bound to an immutable evidence bundle hash
- the VBW output is verifiable (and optionally transparency-logged via Sigstore)
