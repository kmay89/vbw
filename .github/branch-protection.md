# Branch Protection Rules (Manual Configuration Required)

Apply these settings to the `main` branch via GitHub Settings > Branches:

## Required Settings

- [x] **Require a pull request before merging**
  - Required approving reviews: **2**
  - Dismiss stale pull request approvals when new commits are pushed
  - Require review from Code Owners
- [x] **Require status checks to pass before merging**
  - Required checks: `rustfmt`, `clippy`, `test (ubuntu-latest)`, `test (macos-latest)`,
    `cargo-audit`, `cargo-deny (advisories)`, `cargo-deny (licenses)`,
    `cargo-deny (bans)`, `cargo-deny (sources)`, `DCO Sign-off`
  - Require branches to be up to date before merging
- [x] **Require signed commits**
- [x] **Require linear history** (squash or rebase only)
- [x] **Do not allow bypassing the above settings**
- [x] **Restrict who can push to matching branches**
  - Only `scqcs/maintainers` team

## Tag Protection

- Protect tags matching `v*`
- Only `scqcs/maintainers` may create version tags
