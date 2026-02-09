# VBW Demo (Minimal Bundle)

This demo is intentionally minimal and is meant to validate **VBW’s plumbing** and **independence checks**
without requiring SLSA/in-toto/cosign to be installed.

## Run (no external tools)
```bash
cargo build --release
./target/release/vbw verify examples/minimal-bundle --no-external --dry-run --slsa-mode schema-only
cat examples/minimal-bundle/vbw/report.json
```

## What this proves
- Bundle hashing works (evidence is bound to a bundle digest)
- Independence policy runs and reports failures/warnings
- Machine-readable report format is stable for CI

## Next step
Replace `examples/minimal-bundle/provenance.json` with real SLSA provenance and run with:
```bash
vbw verify ./bundle --artifact ./bundle/<your-binary> --source-uri github.com/org/repo
```
