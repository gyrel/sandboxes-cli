# Changelog

## Unreleased

- Match Docker sbx rejection of detached exec with exit status 125.
- Accept `create --no-progress`; create does not emit progress output.

## v0.0.58 — 2026-11-17

### Changed

- `policy ls` reports the reference baseline rules for the allow-all profile
  (`default-allow-all`, `default-fs-read-allow-all`,
  `default-fs-write-allow-all`, `provenance.created_via: "default"`); the table
  uses the reference `POLICY / SOURCE / APPLIES TO / SUMMARY` grouping, and
  `policy inspect` keeps the per-rule detail view.
- `--help` uses the reference layout for every command: `Description`, `Usage`,
  `Aliases`, `Examples`, `Flags` and `Global Flags` with a real flag table. The
  top-level help uses the reference section names and no longer lists `setup`
  twice.

## v0.0.57 — 2026-11-17

### Removed

- Remove the top-level `start`, `get` and `wait` commands. Docker Sandboxes
  `sbx v0.50.1` has no such commands (`sbx start|get|wait` report an unknown
  command); starting a sandbox happens through `run` and `exec`. `stop` keeps
  its table and structured output.

### Changed

- `rsbx ls` prints the reference table: no extra `PROFILE` column, status
  markers (`● running`, `○ stopped`, `◌ <other>`) and week-based ages.
- `version` prints a single client line, matching the reference client, instead
  of also reporting a server line or a dial error when the daemon is stopped.
- An unknown command reports `error: rsbx: unknown command: rsbx <name>` with a
  `try: rsbx --help` hint and exit 1.

### Fixed

- Restore the documented top-level aliases `list`, `remove`, `delete` and
  `secrets`; the legacy sweep removed them because only our README was checked.
- Unknown sandboxes report `sandbox '<name>' not found` with a `try: rsbx ls`
  hint in every command, matching the reference wording and exit codes.
- `rsbx rm` without a target reports `error: requires at least 1 argument` with
  a help hint and exit 1.

## v0.0.55 — 2026-11-17

### Changed

- `rsbx login` now matches the Docker Sandboxes credential flow: an existing
  host account reports `You are signed in` instead of starting a new device
  authorization, the device handoff prints the subscription agreement, the
  one-time code and the sign-in URL, opens the browser without waiting for an
  Enter keypress, and reports `Signed in.` on success. `--username` without
  `--password-stdin` (and the reverse), unknown flags and extra arguments now
  produce `error: ...` with a `try: rsbx login --help` hint and exit 1.
- Account command failures print `error: <message>` like the reference CLI
  instead of a machine code prefix, and a stopped local daemon is reported as
  `local daemon is not running; start it with: rsbx daemon start --detach`
  instead of a raw gRPC dial error.
- `rsbx logout` reports `Signed out.` or `Not signed in.`.

### Fixed

- `rsbx secret set` duplicate-scope errors no longer print a doubled
  `error: error:` prefix.

## v0.0.54 — 2026-11-16

### Removed

- Remove the legacy `create NAME` grammar and the repeated `--workspace` flag.
  `create` now requires `AGENT` and accepts workspace paths only as positional
  `PATH...` arguments.
- Remove undocumented command aliases: top-level `list`, `delete` and `secrets`,
  plus `list` on `kit`, `settings` and `template`. Documented aliases on
  `agents`, `skills` and `secret` remain.
- Remove the dead local policy-profile and domain-evaluation duplicates that
  only tests reached after policy checks moved to the daemon.
- Remove completion suggestions for the unimplemented `secret set-custom` and
  `template save|load|rm` placeholders, and list the implemented policy
  subcommands instead.

### Changed

- Help and README now describe the implemented `policy refresh`, `policy reset`
  and `policy check filesystem` paths, allow `policy.profile=allow-all`, list
  `allow-all` as the default `--policy-profile` value, and state the actual
  allow-all default egress profile.
- Update API to v0.0.28 and Go SDK to v0.0.26; the local RPC contract remains 0.0.27.
- Correct release candidate validation when the changelog begins with `Unreleased`.

### Fixed

- `daemon stop` now stops a daemon that was started outside
  `rsbx daemon start` when its identity can be proven from the live socket
  peer: the peer PID, its process start identity, and a `sandboxesd` executable
  or matching `--socket` argument. It no longer reports `Stopped daemon` while
  the external process keeps running. If the live process cannot be proven, or
  a control record names a different live process, stop refuses without
  signaling and explains how to stop the daemon manually.
- `daemon status` reports a live daemon as running even when no CLI control
  record exists, and continues to report a stopped daemon as stopped. A live
  process whose endpoint is unreachable is reported as running with the error
  and exit status 1, but without a version or API line. Version and API
  information still come only from the live daemon.

## v0.0.53 — 2026-11-16

### Fixed

- `daemon stop` no longer reports success when an endpoint exists without a
  verified daemon control record. It refuses to signal an unverified process
  and explains that an externally started daemon must be stopped manually.
- `daemon start` and `restart` preserve unverified endpoints and control
  records rather than removing state that could belong to another process.
  After a crash, verify any remaining endpoint before removing it manually.

## v0.0.52 — 2026-11-16

### Changed

- `ls`, `rm`, `stop` and `prune` JSON output now matches the Docker sbx shape
  exactly: same envelope, field names, value types and `[]` for empty results.
- `policy ls` returns `{"rules":[...]}`, `settings ls` uses typed values, and
  `diagnose` emits the flat `checks` schema with `message`/`hint`, exiting 0
  when the installation is merely unconfigured.
- Help, `diagnose` and `policy ls` describe allow-all as the default egress
  profile while `deny-all` remains selectable.

## v0.0.51 — 2026-11-16

- `rsbx policy ls --format json|yaml` now emits Docker `sbx`'s policy schema:
  a top-level `{"rules":[...]}` object whose rules carry `id`, `name`,
  `policy_id`, `scope`, `applies_to`, `resource_type`, `decision`, `resources`,
  `origin`, `layer`, `status`, `editable`, `provenance`, `actions` and, for
  scoped rules, `sandbox_id`. The previous bare array with `rule_id`,
  `cidr`/`domain` and `port` is replaced.
- `rsbx policy check network --json|--format yaml` now emits sbx's verdict
  shape with `action`, `allowed`, `context`, `governance`, `resource_type`,
  `resource_value`, `target` and `type`. The table output uses sbx's
  `Allowed:`/`Denied:`, `Governance:` and `Context:` lines. Allow still exits 0
  and deny still exits 1.
- `rsbx settings ls --format json|yaml` and `rsbx settings get --json` now use
  sbx's typed settings records: `value` and `default` are booleans, integers,
  JSON objects/arrays, or strings as the setting type requires; `restart` is
  renamed to `requires_restart`; and `env_var` is included for the settings
  where sbx defines an environment override. File-backed values report source
  `override` like sbx instead of `file`.
- `rsbx diagnose` now treats a signed-out daemon as a warning instead of a
  failure, so a merely unconfigured installation exits 0. The flat report uses
  sbx's `version`, `checks[]` (`name`, `status`, `message`, `detail`, `hint`) and
  `summary` schema, and the advertised `--format github-issue` output produces a
  Markdown issue body with the JSON report embedded. Hard failures, such as an
  unreachable daemon or an unwritable state directory, still exit 1.
- Align `--json` output with Docker `sbx` for `ls`, `rm`, `stop` and `prune`.
  `ls` now emits only `name`, `id`, `agent`, `status`, `last_used_at`,
  `workspaces` and `created_at`; `rm` and `stop` emit arrays of
  `{action, resource, name}` records; and `prune --dry-run` emits
  `{"would_remove":[{name,agent,stopped_at,workspaces}],"skipped_unknown_stop":[]}`
  while actual prune removals use the same action records as `rm`. Human table
  output is unchanged. Structured `start` output still carries operation
  records.
- Accept interspersed flags for `ports`, `policy`, `secret`, `settings`, `cp`,
  `exec`, `get`, `wait`, `agents`, `mcp`, `env`, `kit` and `template`: flags now
  work before, between and after positional arguments, and a literal `--` ends
  flag parsing. `exec` keeps command arguments in order while moving recognized
  exec flags.
- Make help consistent for every command and subcommand: `rsbx CMD --help` and
  `rsbx help CMD` print to stdout and exit 0 instead of writing to stderr,
  printing nothing, or failing with exit 2.
- `rsbx secret set` now refuses to overwrite an existing service secret or
  registry credential without `-f/--force`, in every scope. The error names the
  service or registry, the scope, and tells the user to pass `--force`.
  `rsbx secret import` likewise requires `--force` to replace an existing
  stored value.
- `rsbx secret rm` now exits 0 and prints one line when the credential is not
  stored, for both service and registry credentials. Removing a registry
  credential no longer prints a second misleading `(all-sandboxes)` line when
  only one scope held the credential. Daemon and inventory failures still
  exit 1.
- `rsbx start` now fails closed when the daemon has no runtime backend. The
  daemon still persisted a `running` state for state-only deployments, which
  made the next `exec`, `cp` or `attach` fail with `runtime does not support
  exec`. Start now probes the runtime, reports an actionable error, and restores
  the sandbox to `stopped` instead of announcing a running sandbox it cannot
  back.
- `rsbx get` now supports `-h/--help` on stdout with exit 0, `--format
  table|json|yaml`, and the `--json` shorthand. Unknown flags use the shared
  flag-error contract, and structured output uses the same schema as `rsbx ls`.
  The human table output remains a detailed key/value block. Docker `sbx` has no
  `get` command; the help text documents it as a Rheic extension.
- Add `rsbx daemon start|stop|restart|log-level|status` with the local `sbx
  daemon` grammar. `start`/`restart` support `--detach` and `--policy`;
  `log-level` shows or persists `general`, `proxy` and `all` categories; and
  `status --json` reports the sbx field names `status`, `socket` and `logs`
  plus PID, version, API version and sandbox counts when available.
- Refuse to stop or restart a daemon whose PID, process start identity,
  installation identifier, state directory or socket does not match. Missing,
  stale or unverifiable identity data fails closed, and stale sockets are
  removed only after the recorded process is proven gone and the socket is
  owned by the current user.
- Set `SANDBOXES_DAEMON_BINARY` to choose the daemon binary; otherwise the CLI
  uses `sandboxesd` from PATH or beside `rsbx`, and detached logs go to
  `<state>/daemon.log`.

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
- Destructive `reset` and `policy reset` confirmations now require a terminal
  (or `--force`) and treat an empty answer as cancel, matching `rm` and
  `prune`.
- `rsbx ls --limit N` now caps the number of returned sandboxes instead of
  only setting the daemon page size; without it every sandbox is listed.
- `rsbx rm` now reports unknown flags through the shared error contract
  (`error: unknown flag`, exit 1) like other commands.
- `--socket` is accepted before or after the subcommand, and
  `rsbx help COMMAND` prints that command's help instead of top-level usage.
- The development version fallback is now 0.0.50, with a test that fails when
  it falls behind the latest changelog release.

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
