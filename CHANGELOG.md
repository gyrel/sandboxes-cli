# Changelog

## Unreleased

## v0.0.49 — 2026-11-15

- `rsbx rm` now refuses to delete a running or otherwise non-stopped sandbox
  without `--force`, matching Docker `sbx rm`. When a batch contains an active
  sandbox, every active name is reported and nothing is deleted; `--force`
  still removes running sandboxes and keeps the existing private-clone warning.
- Add `rsbx policy org [--format table|json|yaml]`, a read-only view of the
  effective organization policy bundle. It reports the organization, revision,
  bundle fingerprint, enforcement state, load and expiry times, and parsed
  network rules marked `enforced` or `advisory`. A missing bundle prints a clear
  empty state instead of failing.
- `rsbx policy ls` now prints an `origin` column and best-effort appends
  organization rules when a bundle is loaded, keeping local rules marked
  `local`.
- Consume `github.com/rheic/sandboxes-api` v0.0.26 directly for the additive
  `GetOrgPolicy` RPC. The CLI still uses `sandboxes-go-sdk` for all other
  commands. Downstream builds must bump the API contract; until the API release
  tag exists, this module cannot build standalone without a local replace.

## v0.0.44 — 2026-11-11

- Rebuild the alpha from its immutable tag so release provenance identifies the exact source commit.
- Fix the containerized release workflow and add GitHub Actions workflow linting to CI.


## v0.0.43 — 2026-11-11

- Reject all static remote MCP headers; require host-vault references for every remote header.
- Accept Docker-compatible `--header` syntax for vault placeholders while continuing to reject literal remote header values.
- Update the sandboxes-go-sdk dependency to v0.0.22.
- Reject NUL bytes in vault-backed MCP header names and values.

## v0.0.42 — 2026-11-08

- Redact malformed MCP `--header` and `--secret-header` values from CLI errors.
- Harden tag-triggered release publishing and fix checksum manifest paths in release assets.
- Restrict the installer verification bypass to explicit local-file installs.
- Fail closed if macOS signing, signature verification, or quarantine removal fails.
- Validate installer release-version input before invoking download tools.
- Add `rsbx mcp add --secret-header` so MCP credentials cross RPC only as vault placeholders.
- Add the blue shark symbol mark to the TUI dashboard.
- Update the direct `tcell` dependency to v3.6.0.
- Update the selected `golang.org/x/sys` version from v0.49.0 to v0.50.0.
