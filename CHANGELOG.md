# Changelog

## Unreleased

## v0.0.50 — 2026-11-15

- Validate the daemon-published clone endpoint as a random per-sandbox token
  followed by the repository (`git://127.0.0.1:<port>/<token>/<repository>`).
  Reject legacy tokenless, malformed, or non-hex endpoint paths instead of
  writing an unauthenticated remote. The token is written only into the managed
  remote URL and is refreshed when the daemon rotates it on start.
- `rsbx run` now derives `<agent>-<workspace-basename>` from the current
  directory when no PATH is given, and reuses that sandbox only when its agent,
  image, and workspaces match. A mismatch creates a fresh sandbox instead of
  silently reusing the name.
- Reusing a named sandbox with a different agent is now a hard error unless the
  new `--replace` flag is set, which deletes and recreates the sandbox. A
  different image keeps the existing image and prints a warning on stderr.
- `rsbx prune` and `rsbx run --rm` now print the private-clone commit-loss
  warning used by `rsbx rm`, as does `run --replace` when it removes a clone.
- `rsbx run --docker` now parses and forwards the dedicated Docker profile instead of rejecting the flag documented in its help.
- `rsbx run --deny-write PATH` now keeps the default current-directory workspace (or the explicit workspace set) and adds PATH as a read-only mount, rather than replacing the workspace set. A path inside a workspace becomes a read-only subpath mount; equal or enclosing paths are rejected as overlapping mounts.

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
