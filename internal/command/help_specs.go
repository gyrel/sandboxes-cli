package command

const (
	helpNameDetach      = "detach"
	helpNameDocker      = "docker"
	helpNameEnv         = "env"
	helpNameEnvFile     = "env-file"
	helpNameForce       = "force"
	helpNameImage       = "image"
	helpNameInt         = "int"
	helpNameLimit       = "limit"
	helpNameName        = "name"
	helpNamePublish     = "publish"
	helpNameQuiet       = "quiet"
	helpNameMethod      = "method"
	helpNameSandbox     = "sandbox"
	helpNameStringArray = "stringArray"
	helpNameWrite       = "write"
	helpNameRegistry    = "registry"
	helpNameEnvArg      = "env-arg"
	helpNameEnvArgsFile = "env-args-file"
	helpNameAll         = "all"
	helpNamePlan        = "plan"
	helpNameAdd         = "add"
	helpNameCall        = "call"
	helpNameCheck       = "check"
	helpNameInit        = "init"
	helpNameLog         = "log"
	helpNameProfile     = "profile"
	helpNameRefresh     = "refresh"
	helpNameBash        = "bash"
	helpNameFish        = "fish"
	helpNamePowershell  = "powershell"
	helpNameZsh         = "zsh"
	helpNameFormat      = "format"
	helpValueString     = "string"
	helpValueName       = "NAME"
	helpNameUser        = "user"

	helpFormatDescription      = "Output format: table, json or yaml"
	helpJSONDescription        = "Output in JSON format"
	helpFormatLowerDescription = "output format: table, json or yaml"
	helpJSONLowerDescription   = "output in JSON format"
	helpEnvArgDescription      = "set a declared environment argument (repeatable)"
	helpEnvFileDescription     = "read environment overrides from a file (repeatable)"
	helpUserDescription        = "uid[:gid] or name[:group]"
	helpApplyNoPrompt          = "apply without prompting"
	helpEnvNameDescription     = "override the environment sandbox name"
	helpAliasList              = "ls, list"
	helpEnvArgsFileDescription = "read name=value arguments (repeatable)"
)

// This file centralizes the structured --help content for every implemented
// command. Flag lists mirror the flag sets in the command handlers exactly.

func runHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Run an agent in a local sandbox, creating the sandbox if it does not already exist.",
			"",
			"Create a local sandbox, start it, and attach to an agent. This command uses the",
			"local Rheic daemon; cloud sandboxes and remote/OCI kits are not supported here.",
			"The default workspace is the current directory. Pass additional workspace paths",
			"after PATH; append :ro to make a workspace read-only. Agent arguments after -- are",
			"passed to the agent.",
			"",
			"Without --name, the sandbox name is <agent>-<workspace-basename>. An existing sandbox",
			"with that name is reused only when its agent, image, and workspaces match: on a",
			"terminal, rsbx asks first; without a terminal, it reuses automatically. --new always",
			"creates a fresh sandbox. With --name, rsbx reuses and restarts that sandbox unless",
			"--new is also set. --replace deletes and recreates an existing --name sandbox.",
			"With --detach, rsbx creates or starts the sandbox, prints its ID, and exits.",
			"--rm removes the sandbox after the attached agent session exits.",
		},
		Usage: []string{
			"rsbx run [flags] [AGENT] [PATH...] [-- AGENT_ARGS...]",
		},
		Examples: []string{
			"rsbx run shell",
			"rsbx run codex ./project /path/to/docs:ro",
			"rsbx run shell -- --version",
			"rsbx run --name dev-shell --detach shell",
			"",
			"# Create a fresh sandbox even when the name already exists",
			"rsbx run --new --name clean-shell --detach shell",
		},
		Flags: []commandFlagHelp{
			{Name: "allow-network", Value: helpNameStringArray, Description: "allow egress CIDR rule (repeatable; optional udp: prefix)"},
			{Name: cloneName, Description: "run on a private in-guest clone of the host Git repository"},
			{Name: "cpus", Value: helpNameInt, Description: "CPUs for a new sandbox (0 selects the daemon default)"},
			{Name: "deny-network", Value: helpNameStringArray, Description: "deny egress CIDR rule (repeatable; optional udp: prefix)"},
			{Name: "deny-write", Value: helpNameStringArray, Description: "keep selected workspaces and add PATH read-only (repeatable)"},
			{Short: "d", Name: helpNameDetach, Description: "create and start without attaching"},
			{Name: helpNameDocker, Description: "run the dedicated Docker profile"},
			{Short: "e", Name: helpNameEnv, Value: helpNameStringArray, Description: "environment override for the agent session (repeatable)"},
			{Name: helpNameEnvFile, Value: helpNameStringArray, Description: helpEnvFileDescription},
			{Short: "h", Name: helpCommand, Description: "help for run"},
			{Name: helpNameImage, Value: helpValueString, Description: "image reference override for a new sandbox"},
			{Name: "kit", Value: helpValueString, Description: "apply a local kit definition"},
			{Short: "m", Name: "memory", Value: helpValueString, Description: "memory limit for a new sandbox, such as 512m or 2g"},
			{Name: helpNameName, Value: helpValueString, Description: "sandbox name; reuse and restart it when it already exists"},
			{Name: "new", Description: "always create a new sandbox instead of reusing the named one"},
			{Name: "no-progress", Description: "suppress progress output"},
			{Name: "policy-profile", Value: helpValueString, Description: "allow-all (default), deny-all, balanced, or sbx-compat"},
			{Short: "p", Name: helpNamePublish, Value: helpNameStringArray, Description: "publish a guest port (repeatable): [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6]"},
			{Name: "replace", Description: "delete and recreate an existing --name sandbox before running"},
			{Name: "rm", Description: "remove the sandbox after the agent session exits"},
			{Name: "skills", Value: "MODE", Description: "shared skills mode for a new sandbox only: off, readonly, or readwrite (unsupported); an omitted flag uses the skills.defaultMode setting (default readonly); reuse keeps the existing mode"},
			{Short: "t", Name: "template", Value: helpValueString, Description: "container image for a new sandbox (alias for --image)"},
		},
	}
}

func createHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Create a sandbox with access to a host workspace for an agent.",
			"",
			"The first positional argument is a registered agent name (built-in or custom). Omit the path to create a",
			"sandbox without a workspace bind mount: the agent then works in the container's",
			"own filesystem instead of on your files. Use \"rsbx run --name SANDBOX\" to attach",
			"to the agent after creation.",
			"",
			"Additional paths may be mounted read-only by appending :ro or :readonly. --clone",
			"uses a read-only host Git source and a private in-guest clone.",
		},
		Usage: []string{
			"rsbx create AGENT [PATH...] [flags]",
		},
		Examples: []string{
			"# Create a sandbox for Claude in the current directory",
			"rsbx create claude .",
			"",
			"# Create a sandbox with a custom name",
			"rsbx create --name my-project claude /path/to/project",
			"",
			"# Create with additional read-only workspaces",
			"rsbx create claude . /path/to/docs:ro",
			"",
			"# Create without a workspace bind mount",
			"rsbx create claude",
		},
		Flags: []commandFlagHelp{
			{Name: "allow-network", Value: helpNameStringArray, Description: "allow egress CIDR[:PORT] (repeatable; optional udp: prefix)"},
			{Name: cloneName, Description: "run the agent on a private in-guest clone of PATH"},
			{Name: "cpus", Value: "uint", Description: "CPUs (0 selects the daemon default)"},
			{Name: "deny-network", Value: helpNameStringArray, Description: "deny egress CIDR[:PORT] (repeatable; optional udp: prefix)"},
			{Name: "deny-write", Value: helpNameStringArray, Description: "mount PATH read-only (repeatable)"},
			{Name: "skills", Value: "MODE", Description: "shared skills mode for a new sandbox only: off, readonly, or readwrite (unsupported); an omitted flag uses the skills.defaultMode setting (default readonly); reuse keeps the existing mode"},
			{Name: helpNameDocker, Description: "run the dedicated Docker profile"},
			{Short: "e", Name: helpNameEnv, Value: helpNameStringArray, Description: "environment KEY=VALUE for every process (repeatable)"},
			{Name: helpNameEnvFile, Value: helpNameStringArray, Description: "read environment from a file (repeatable)"},
			{Short: "h", Name: helpCommand, Description: "help for create"},
			{Name: "idempotency-key", Value: helpValueString, Description: "idempotency key"},
			{Name: helpNameImage, Value: helpValueString, Description: "image reference"},
			{Name: "kit", Value: helpValueString, Description: "apply a local kit definition"},
			{Short: "m", Name: "memory", Value: helpValueString, Description: "memory limit such as 512m or 2g (empty selects the daemon default)"},
			{Name: helpNameName, Value: helpValueString, Description: "sandbox name"},
			{Name: "no-progress", Description: "suppress progress output"},
			{Name: "policy-profile", Value: helpValueString, Description: "egress profile: allow-all, balanced, deny-all or sbx-compat"},
			{Short: "p", Name: helpNamePublish, Value: helpNameStringArray, Description: "publish a guest port (repeatable): [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6]"},
			{Short: "t", Name: "template", Value: helpValueString, Description: "container image to use for the sandbox (alias for --image)"},
		},
	}
}

func attachHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Attach an interactive terminal session to a sandbox.",
			"",
			"The sandbox must already exist; a stopped one is started first. The sandbox's",
			"agent command is used unless --shell is set.",
		},
		Usage: []string{"rsbx attach SANDBOX [flags]"},
		Examples: []string{
			"# Attach to a sandbox by name",
			"rsbx attach my-sandbox",
		},
		Flags: []commandFlagHelp{
			{Short: "h", Name: helpCommand, Description: "help for attach"},
			{Name: "shell", Description: "open /bin/sh instead of the agent command"},
		},
	}
}

func cpHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Copy files between the host and a sandbox.",
			"",
			"Exactly one of SRC or DST must be a sandbox path, written as SANDBOX:PATH.",
			"The other must be a local path. Copying between two sandboxes is not supported.",
			"When copying a directory, the directory itself is placed at the destination.",
			"Symbolic links, hard links and special files are rejected by default.",
			"-L follows a top-level source symbolic link; nested links remain rejected.",
		},
		Usage: []string{"rsbx cp SRC DST [flags]"},
		Examples: []string{
			"# Copy a file from host to sandbox",
			"rsbx cp ./config.json my-sandbox:/home/user/",
			"",
			"# Copy a file from sandbox to host",
			"rsbx cp my-sandbox:/home/user/output.log ./",
		},
		Flags: []commandFlagHelp{
			{Short: "L", Name: "follow-link", Description: "follow a top-level source symbolic link"},
			{Short: "h", Name: helpCommand, Description: "help for cp"},
		},
	}
}

func execHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Execute a command in a sandbox. If the sandbox is stopped, it is started first.",
			"",
			"Flags may appear before, between or after arguments; use -- to end flag parsing.",
			"The local daemon/runtime provides no per-exec privilege escalation: --privileged is",
			"rejected explicitly instead of being ignored. --detach-keys is accepted for parity",
			"with the reference CLI, which applies it only to an interactive cloud exec.",
			"Exit status is that of the command. rsbx exits 125 if it could not run the command,",
			"for example because the sandbox does not exist.",
		},
		Usage: []string{"rsbx exec [flags] SANDBOX COMMAND [ARG...]"},
		Examples: []string{
			"# Open a shell inside a sandbox",
			"rsbx exec -it my-sandbox bash",
			"",
			"# Run as root",
			"rsbx exec -u root my-sandbox apt-get update",
		},
		Flags: []commandFlagHelp{
			{Short: "d", Name: "detach", Description: "detached mode (not supported)"},
			{Name: "detach-keys", Value: helpValueString, Description: "override the key sequence for detaching a container (cloud interactive exec only)"},
			{Short: "e", Name: helpNameEnv, Value: helpNameStringArray, Description: "environment override (repeatable)"},
			{Name: helpNameEnvFile, Value: helpNameStringArray, Description: helpEnvFileDescription},
			{Short: "h", Name: helpCommand, Description: "help for exec"},
			{Short: "i", Name: interactiveName, Description: "keep stdin open"},
			{Name: privilegedName, Description: "give extended privileges to the command (unsupported by the local runtime; rejected explicitly)"},
			{Short: "t", Name: ttyName, Description: "allocate a terminal"},
			{Short: "u", Name: helpNameUser, Value: helpValueString, Description: helpUserDescription},
			{Short: "w", Name: "workdir", Value: helpValueString, Description: "guest working directory"},
		},
	}
}

func listHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"List all sandboxes with their agent, status, published ports, and workspace.",
			"",
			"table is the default; --json is equivalent to --format json; -q prints only names.",
			"--limit N returns at most N sandboxes (1-1000); without it every sandbox is listed.",
		},
		Usage:   []string{"rsbx ls [flags]"},
		Aliases: []string{helpAliasList},
		Examples: []string{
			"rsbx ls",
			"rsbx ls --json",
			"rsbx ls --limit 10 --format yaml",
			"",
			"# Names only, for scripting",
			"rsbx ls -q",
			"",
			"# Machine-readable output",
			"rsbx ls --format json",
		},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatDescription},
			{Short: "h", Name: helpCommand, Description: "help for ls"},
			{Name: listFormatJSON, Description: helpJSONDescription},
			{Name: helpNameLimit, Value: helpNameInt, Description: "maximum number of sandboxes to return (1-1000; default all)"},
			{Short: "q", Name: helpNameQuiet, Description: "Only display sandbox names"},
		},
	}
}

func stopHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Stop one or more running sandboxes without removing them.",
			"",
			"Stopped sandboxes retain their state and can be restarted with \"rsbx run\".",
			"Flags may appear before, between or after sandbox names; use -- to end flag parsing.",
			"Structured output is an array of {action, resource, name} records, matching sbx stop --json.",
		},
		Usage: []string{"rsbx stop SANDBOX... [flags]"},
		Examples: []string{
			"rsbx stop my-sandbox",
			"rsbx stop --format json api",
			"rsbx stop api --format json",
			"",
			"# Stop several at once",
			"rsbx stop one two",
		},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatDescription},
			{Name: "grace", Value: "duration", Description: "stop grace period"},
			{Short: "h", Name: helpCommand, Description: "help for stop"},
			{Name: listFormatJSON, Description: helpJSONDescription},
		},
	}
}

func removeHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Remove one or more sandboxes.",
			"",
			"Without --force, every named sandbox must be stopped: if any sandbox is running or",
			"otherwise not stopped, the whole command fails and nothing is removed. Stop those",
			"sandboxes first, or pass --force to remove them anyway. --force also skips",
			"confirmation. --all removes every sandbox. Structured output is an array of",
			"{action, resource, name} records, matching sbx rm --json.",
			"",
			"Host-mount directories and persistent storage are kept. This action cannot be undone.",
		},
		Usage:   []string{"rsbx rm [SANDBOX...] [flags]"},
		Aliases: []string{"rm, remove, delete"},
		Examples: []string{
			"rsbx rm my-sandbox",
			"rsbx rm --force api",
			"rsbx rm api --force",
			"",
			"# Remove several at once",
			"rsbx rm one two",
			"",
			"# Remove every sandbox without asking",
			"rsbx rm --all --force",
		},
		Flags: []commandFlagHelp{
			{Name: helpNameAll, Description: "Remove all sandboxes"},
			{Short: "f", Name: helpNameForce, Description: "Skip confirmation prompts and allow running sandboxes"},
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatDescription},
			{Short: "h", Name: helpCommand, Description: "help for rm"},
			{Name: listFormatJSON, Description: helpJSONDescription},
		},
	}
}

func pruneHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Remove all stopped sandboxes and their associated resources.",
			"",
			"Only stopped sandboxes are candidates; a running sandbox is never removed. Use",
			"--filter until=TIMESTAMP to narrow the set to sandboxes that stopped before",
			"TIMESTAMP. The value can be an RFC 3339 timestamp, Unix timestamp, or a Go duration",
			"relative to now (for example until=168h). A sandbox whose stop time the daemon",
			"cannot report is left alone.",
			"",
			"Use --dry-run to list what would be removed without removing anything. Pruning",
			"requires confirmation; use --force to skip the prompt. This action cannot be undone.",
		},
		Usage: []string{"rsbx prune [flags]"},
		Examples: []string{
			"# Show what would be removed",
			"rsbx prune --dry-run",
			"",
			"# Remove without asking",
			"rsbx prune --force",
			"",
			"# Only sandboxes stopped before a point in time",
			"rsbx prune --filter until=2026-01-01T00:00:00Z",
		},
		Flags: []commandFlagHelp{
			{Name: dryRunName, Description: "List the sandboxes that would be removed without removing them"},
			{Name: "filter", Value: helpValueString, Description: "Filter candidates (supported: until=TIMESTAMP or until=DURATION)"},
			{Short: "f", Name: helpNameForce, Description: "Skip confirmation prompts and remove even if in use"},
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatDescription},
			{Short: "h", Name: helpCommand, Description: "help for prune"},
			{Name: listFormatJSON, Description: helpJSONDescription},
		},
	}
}

func portsHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Manage sandbox port publishing.",
			"",
			"List, publish, or unpublish sandbox ports. Publishing a local port starts a stopped",
			"sandbox before creating the host binding. Without --publish or --unpublish flags,",
			"lists all published ports.",
			"",
			"Port spec format: [[HOST_IP:]HOST_PORT:]SANDBOX_PORT[/PROTOCOL]",
			"Supported protocols: tcp, tcp4, tcp6, udp, udp4, udp6.",
		},
		Usage: []string{"rsbx ports SANDBOX [flags]"},
		Examples: []string{
			"# List published ports",
			"rsbx ports my-sandbox",
			"",
			"# Publish sandbox port 8080 to an ephemeral host port",
			"rsbx ports my-sandbox --publish 8080",
			"",
			"# Unpublish a port",
			"rsbx ports my-sandbox --unpublish 3000:8080",
		},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatDescription},
			{Short: "h", Name: helpCommand, Description: "help for ports"},
			{Name: listFormatJSON, Description: helpJSONDescription},
			{Name: helpNamePublish, Value: helpNameStringArray, Description: "publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6] (repeatable)"},
			{Name: "unpublish", Value: helpNameStringArray, Description: "unpublish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6] (repeatable)"},
		},
	}
}

func daemonHelp() commandHelp {
	return commandHelp{
		Description: []string{"Manage the local sandboxesd daemon."},
		Usage:       []string{"rsbx daemon COMMAND"},
		AvailableCommands: []commandSummary{
			{Name: "log-level", Description: "Show or change sandboxesd's per-category log levels"},
			{Name: "restart", Description: "Restart the sandboxesd daemon"},
			{Name: "start", Description: "Start the sandboxesd daemon"},
			{Name: "status", Description: "Show sandboxesd daemon status"},
			{Name: "stop", Description: "Stop the sandboxesd daemon"},
		},
		Flags:  []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for daemon"}},
		Footer: "Use \"rsbx daemon COMMAND --help\" for more information about a command.",
	}
}

func daemonStartHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Start the local daemon in the foreground; use --detach to run it in the",
			"background with logs in <state>/daemon.log.",
		},
		Usage: []string{"rsbx daemon start [flags]"},
		Flags: []commandFlagHelp{
			{Short: "d", Name: helpNameDetach, Description: "Run the daemon in the background"},
			{Short: "h", Name: helpCommand, Description: "help for daemon start"},
			{Name: "policy", Value: helpValueString, Description: "Initialize policy: allow-all, balanced or deny-all"},
		},
	}
}

func daemonStopHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Stop the local daemon. A stopped daemon is not an error.",
			"",
			"A daemon started outside 'rsbx daemon start' is stopped only after its identity",
			"is proven from the control record or the live socket peer. If identity cannot be",
			"proven, stop refuses and explains how to stop the daemon manually.",
		},
		Usage: []string{"rsbx daemon stop [flags]"},
		Flags: []commandFlagHelp{
			{Short: "h", Name: helpCommand, Description: "help for daemon stop"},
		},
	}
}

func daemonRestartHelp() commandHelp {
	return commandHelp{
		Description: []string{"Stop the proven local daemon process, then start a new one."},
		Usage:       []string{"rsbx daemon restart [flags]"},
		Flags: []commandFlagHelp{
			{Short: "d", Name: helpNameDetach, Description: "Run the daemon in the background"},
			{Short: "h", Name: helpCommand, Description: "help for daemon restart"},
			{Name: "policy", Value: helpValueString, Description: "Initialize policy: allow-all, balanced or deny-all"},
		},
	}
}

func daemonLogLevelHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Show the general and proxy log levels, or persist a new level. TARGET is",
			"general, proxy or all. LEVEL is debug, info, warn or error. A single LEVEL",
			"sets every category.",
		},
		Usage: []string{
			"rsbx daemon log-level [LEVEL]",
			"rsbx daemon log-level set TARGET LEVEL",
		},
		Examples: []string{
			"rsbx daemon log-level",
			"rsbx daemon log-level set general debug",
			"rsbx daemon log-level set all info",
			"rsbx daemon log-level warn",
		},
		Flags: []commandFlagHelp{
			{Short: "h", Name: helpCommand, Description: "help for daemon log-level"},
		},
	}
}

func daemonStatusHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Show daemon status from the live endpoint. JSON uses the sbx field names",
			"status, socket and logs, plus pid, version, api_version, sandboxes, running,",
			"stopped and error when available.",
		},
		Usage: []string{"rsbx daemon status [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatDescription},
			{Short: "h", Name: helpCommand, Description: "help for daemon status"},
			{Name: listFormatJSON, Description: helpJSONDescription},
		},
	}
}

func diagnoseHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Diagnose common issues with your rsbx installation.",
			"",
			"Checks host installation, platform, storage and daemon connection. JSON and YAML",
			"use sbx's flat report schema: version, checks[] with name, status, message, detail",
			"and hint, plus a summary. github-issue emits a Markdown issue body with the JSON",
			"report embedded.",
			"",
			"Exit 0 when every check passes, warns or is skipped; exit 1 only when a check fails.",
		},
		Usage: []string{"rsbx diagnose [flags]"},
		Examples: []string{
			"rsbx diagnose",
			"",
			"# Print the report as JSON",
			"rsbx diagnose --format json",
		},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: "Output format: table, json, yaml or github-issue"},
			{Short: "h", Name: helpCommand, Description: "help for diagnose"},
			{Name: listFormatJSON, Description: helpJSONDescription},
		},
	}
}

func envHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Manage a sandbox declared in an sbxenv.yaml file. The file selects the agent,",
			"kits, workspace mounts, environment variables, secrets, and credential bindings.",
			"",
			"Use create to provision the sandbox, run to start or join its agent session,",
			"exec to run a command, and rm to remove it and its provisioned secrets.",
			"Use plan to preview changes. Changes require approval; --force skips the prompt.",
			"",
			"Environment values are never displayed.",
		},
		Usage: []string{"rsbx env COMMAND"},
		AvailableCommands: []commandSummary{
			{Name: commandCreate, Description: "Create a sandbox environment from sbxenv.yaml"},
			{Name: "exec", Description: "Execute a command inside a sandbox environment"},
			{Name: helpNamePlan, Description: "Show what an environment would change outside the sandbox"},
			{Name: "rm", Description: "Remove a sandbox environment and its scoped resources"},
			{Name: "run", Description: "Create (if needed) and attach to a sandbox environment"},
		},
		Flags:  []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for env"}},
		Footer: "Use \"rsbx env COMMAND --help\" for more information about a command.",
	}
}

func envPlanHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Show a static preview of the environment plan.",
			"",
			"Without PATH, read sbxenv.yaml from the current directory and merge optional",
			"~/.sbxenv.yaml defaults first. Explicit file or directory paths merge in order and",
			"skip user defaults. Values passed through --env-arg may be visible in host process",
			"listings; use --env-args-file for sensitive values. This is a static preview only;",
			"it does not apply changes or inspect daemon state.",
		},
		Usage: []string{"rsbx env plan [PATH...] [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameEnvArg, Value: helpNameStringArray, Description: "set a declared environment argument (repeatable; overrides files)"},
			{Name: helpNameEnvArgsFile, Value: helpNameStringArray, Description: helpEnvArgsFileDescription},
			{Short: "h", Name: helpCommand, Description: "help for env plan"},
			{Name: helpNameName, Value: helpValueString, Description: "override the sandbox name"},
		},
	}
}

func envCreateHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Apply the supported environment plan and create a sandbox without attaching.",
			"Unsupported fields fail closed.",
		},
		Usage: []string{"rsbx env create [PATH...] [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameEnvArg, Value: helpNameStringArray, Description: helpEnvArgDescription},
			{Name: helpNameEnvArgsFile, Value: helpNameStringArray, Description: helpEnvArgsFileDescription},
			{Short: "f", Name: helpNameForce, Description: helpApplyNoPrompt},
			{Short: "h", Name: helpCommand, Description: "help for env create"},
			{Name: helpNameName, Value: helpValueString, Description: helpEnvNameDescription},
		},
	}
}

func envExecHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Runs a command in a matching existing environment sandbox, starting it if stopped.",
			"Without --, positional arguments are the command and the environment path defaults",
			"to the current directory.",
			"Execution flags match rsbx exec, including its explicit rejection of --privileged",
			"because the local daemon/runtime cannot add per-exec privileges. --detach-keys is",
			"accepted for parity; the reference CLI applies it only to an interactive cloud exec.",
		},
		Usage: []string{"rsbx env exec [flags] [PATH...] [-- COMMAND [ARG...]]"},
		Flags: []commandFlagHelp{
			{Short: "d", Name: helpNameDetach, Description: "detached mode (not supported)"},
			{Name: "detach-keys", Value: helpValueString, Description: "override the key sequence for detaching a container (cloud interactive exec only)"},
			{Short: "e", Name: helpNameEnv, Value: helpNameStringArray, Description: "environment override (repeatable)"},
			{Name: helpNameEnvArg, Value: helpNameStringArray, Description: helpEnvArgDescription},
			{Name: helpNameEnvArgsFile, Value: helpNameStringArray, Description: helpEnvArgsFileDescription},
			{Name: helpNameEnvFile, Value: helpNameStringArray, Description: helpEnvFileDescription},
			{Short: "f", Name: helpNameForce, Description: helpApplyNoPrompt},
			{Short: "h", Name: helpCommand, Description: "help for env exec"},
			{Short: "i", Name: interactiveName, Description: "keep stdin open"},
			{Name: helpNameName, Value: helpValueString, Description: helpEnvNameDescription},
			{Name: privilegedName, Description: "give extended privileges to the command (unsupported by the local runtime; rejected explicitly)"},
			{Short: "t", Name: ttyName, Description: "allocate a terminal"},
			{Short: "u", Name: helpNameUser, Value: helpValueString, Description: helpUserDescription},
			{Short: "w", Name: "workdir", Value: helpValueString, Description: "guest working directory"},
		},
	}
}

func envRunHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Create an environment if absent, then start and attach to its configured agent.",
			"Existing matching sandboxes are reused without re-provisioning.",
		},
		Usage: []string{"rsbx env run [PATH...] [flags] [-- AGENT-ARGS...]"},
		Flags: []commandFlagHelp{
			{Short: "d", Name: helpNameDetach, Description: "start without attaching"},
			{Name: helpNameEnvArg, Value: helpNameStringArray, Description: helpEnvArgDescription},
			{Name: helpNameEnvArgsFile, Value: helpNameStringArray, Description: helpEnvArgsFileDescription},
			{Short: "f", Name: helpNameForce, Description: helpApplyNoPrompt},
			{Short: "h", Name: helpCommand, Description: "help for env run"},
			{Name: helpNameName, Value: helpValueString, Description: helpEnvNameDescription},
		},
	}
}

func envRemoveHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Remove the sandbox matching this environment's name, agent, and workspace.",
			"Global credential bindings are not removed.",
		},
		Usage: []string{"rsbx env rm [PATH...] [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameEnvArg, Value: helpNameStringArray, Description: helpEnvArgDescription},
			{Name: helpNameEnvArgsFile, Value: helpNameStringArray, Description: helpEnvArgsFileDescription},
			{Short: "f", Name: helpNameForce, Description: helpApplyNoPrompt},
			{Short: "h", Name: helpCommand, Description: "help for env rm"},
			{Name: helpNameName, Value: helpValueString, Description: helpEnvNameDescription},
		},
	}
}

func loginHelp() commandHelp {
	return commandHelp{
		Description: []string{"Sign in to Docker."},
		Usage:       []string{"rsbx login [flags]"},
		Examples: []string{
			"rsbx login",
			"",
			"# Non-interactive sign-in, for CI",
			"echo \"$DOCKER_PAT\" | rsbx login --username me --password-stdin",
		},
		Flags: []commandFlagHelp{
			{Short: "h", Name: helpCommand, Description: "help for login"},
			{Name: "password-stdin", Description: "Read password or access token from stdin"},
			{Name: "username", Value: helpValueString, Description: "Docker username for non-interactive login"},
		},
	}
}

func logoutHelp() commandHelp {
	return commandHelp{
		Description: []string{"Stop running local sandboxes and sign out of Docker."},
		Usage:       []string{"rsbx logout [flags]"},
		Examples: []string{
			"rsbx logout",
			"",
			"# Skip the confirmation prompt",
			"rsbx logout --force",
		},
		Flags: []commandFlagHelp{
			{Short: "f", Name: helpNameForce, Description: "Skip confirmation prompt"},
			{Short: "h", Name: helpCommand, Description: "help for logout"},
		},
	}
}

func mcpHelp() commandHelp {
	return commandHelp{
		Description: []string{"Register and manage MCP servers for use with sandbox sessions."},
		Usage:       []string{"rsbx mcp COMMAND"},
		AvailableCommands: []commandSummary{
			{Name: helpNameAdd, Description: "Register an MCP server"},
			{Name: helpNameCall, Description: "Call a tool on a registered MCP server"},
			{Name: "ls", Description: "List MCP servers"},
			{Name: "rm", Description: "Remove a registered MCP server"},
		},
		Flags:  []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for mcp"}},
		Footer: "Use \"rsbx mcp COMMAND --help\" for more information about a command.",
	}
}

func mcpListHelp() commandHelp {
	return commandHelp{
		Description: []string{"List registered MCP servers."},
		Usage:       []string{"rsbx mcp ls [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: "output format: table or json"},
			{Short: "h", Name: helpCommand, Description: "help for mcp ls"},
			{Name: listFormatJSON, Description: "write JSON"},
			{Name: helpNameQuiet, Description: "print server names only"},
		},
	}
}

func mcpAddHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Register an MCP server.",
			"",
			"Local stdio servers are registered with --command. Remote servers use --url.",
			"Both remote header flags accept host-vault references only; literal values are",
			"rejected. Store values with rsbx secret set mcp:NAME:PLACEHOLDER. Remote servers",
			"are limited to the daemon's allowed hosts.",
		},
		Usage: []string{
			"rsbx mcp add NAME --command EXECUTABLE [--args ARG] [--dir PATH]",
			"rsbx mcp add NAME --url https://HOST/mcp [--header|--secret-header 'Name: value with ${PLACEHOLDER}']",
		},
		Flags: []commandFlagHelp{
			{Name: "args", Value: helpNameStringArray, Description: "comma-separated MCP executable arguments (repeatable)"},
			{Name: commandName, Value: helpValueString, Description: "absolute or PATH-resolved local stdio executable"},
			{Name: "dir", Value: helpValueString, Description: "working directory"},
			{Name: "header", Value: helpNameStringArray, Description: "Docker-compatible alias for a host-vault remote header; values must contain ${placeholder}"},
			{Short: "h", Name: helpCommand, Description: "help for mcp add"},
			{Name: "secret-header", Value: helpNameStringArray, Description: "host-vault remote header as Name:Value with ${placeholder}"},
			{Name: "url", Value: helpValueString, Description: "remote streamable-HTTPS MCP endpoint (mutually exclusive with --command)"},
		},
	}
}

func mcpCallHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Call a tool on a registered MCP server.",
			"",
			"Requests daemon-trusted approval before invoking the host MCP server. Argument",
			"values are hidden in the prompt; do not pass secrets.",
		},
		Usage: []string{"rsbx mcp call SANDBOX SERVER TOOL [flags]"},
		Flags: []commandFlagHelp{
			{Name: "args", Value: helpValueString, Description: "JSON object passed to the tool (default {})"},
			{Short: "h", Name: helpCommand, Description: "help for mcp call"},
		},
	}
}

func mcpRemoveHelp() commandHelp {
	return commandHelp{
		Description: []string{"Remove an MCP server registration."},
		Usage:       []string{"rsbx mcp rm NAME [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameForce, Description: "skip confirmation"},
			{Short: "h", Name: helpCommand, Description: "help for mcp rm"},
		},
	}
}

func policyHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Manage persistent access policies for sandboxes.",
			"",
			"Policies contain rules that control what sandboxes can access. Local rules can",
			"apply globally across all sandboxes or be scoped to one sandbox. Use subcommands",
			"to allow, deny, list, or remove rules.",
			"",
			"Default is allow-all, matching the Docker sbx baseline; deny-all remains selectable.",
		},
		Usage: []string{"rsbx policy COMMAND"},
		AvailableCommands: []commandSummary{
			{Name: "allow", Description: "Add an allow rule for sandboxes"},
			{Name: helpNameCheck, Description: "Check whether policy allows an access request"},
			{Name: "deny", Description: "Add a deny rule for sandboxes"},
			{Name: helpNameInit, Description: "Initialize the global network policy"},
			{Name: commandInspect, Description: "Show policy or rule details"},
			{Name: helpNameLog, Description: "Show sandbox policy logs"},
			{Name: "ls", Description: "List sandbox policies"},
			{Name: "org", Description: "Show the effective organization policy"},
			{Name: helpNameProfile, Description: "Show the global default policy profile"},
			{Name: helpNameRefresh, Description: "Force an immediate policy refresh"},
			{Name: "reset", Description: "Reset policies to defaults"},
			{Name: "rm", Description: "Remove a policy rule"},
		},
		Flags:  []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for policy"}},
		Footer: "Use \"rsbx policy COMMAND --help\" for more information about a command.",
	}
}

func policyListHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"List global and sandbox allow/deny rules.",
			"",
			"Without SANDBOX, the command shows one overview row per policy. With",
			"SANDBOX, it summarizes active rules that apply to that sandbox.",
			"",
			"Use --wide to show detailed rule-level rows with RULE_ID, STATUS and resources.",
			"Use --quiet to print only rule IDs. --quiet cannot be combined with",
			"--wide, --json or --format.",
			"Org rules that remote governance does not enforce are inactive and hidden",
			"unless --include-inactive is set.",
		},
		Usage: []string{"rsbx policy ls [SANDBOX] [flags]"},
		Examples: []string{
			"rsbx policy ls",
			"rsbx policy ls my-sandbox",
			"rsbx policy ls --wide",
			"rsbx policy ls --json",
			"rsbx policy ls -q",
			"rsbx policy ls --type network",
			"rsbx policy ls --source local --decision deny",
			"rsbx policy ls --include-inactive",
		},
		Flags: []commandFlagHelp{
			{Name: "created-via", Value: helpValueString, Description: "filter policies by creation method: default, added or provisioned"},
			{Name: "decision", Value: helpValueString, Description: "filter policies by decision: allow or deny"},
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for policy ls"},
			{Name: "include-inactive", Description: "show inactive policy rules hidden by remote governance"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
			{Name: helpNameProfile, Value: helpValueString, Description: "filter policies by governance profile (unsupported)"},
			{Name: "protocol", Value: helpValueString, Description: "filter network rules by protocol: tcp or udp"},
			{Short: "q", Name: "quiet", Description: "only display rule IDs"},
			{Name: "source", Value: helpValueString, Description: "filter policies by source: local, org or kit"},
			{Name: "type", Value: helpValueString, Description: "filter policies by type: all, network or filesystem"},
			{Name: "wide", Description: "show detailed rule-level output with rule IDs and resources"},
		},
	}
}

func policyInspectHelp() commandHelp {
	return commandHelp{
		Description: []string{"Show one rule by ID or one sandbox's policy in detail."},
		Usage:       []string{"rsbx policy inspect RULE_ID|SANDBOX [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for policy inspect"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
		},
	}
}

func policyLogHelp() commandHelp {
	return commandHelp{
		Description: []string{"Show gateway audit decisions."},
		Usage:       []string{"rsbx policy log [SANDBOX] [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for policy log"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
			{Name: helpNameLimit, Value: helpNameInt, Description: "maximum number of log entries to show (0 = all)"},
			{Name: "type", Value: helpValueString, Description: "filter logs by type: all or network"},
		},
	}
}

func policyRefreshHelp() commandHelp {
	return commandHelp{
		Description: []string{"Re-apply the effective policy to running sandboxes."},
		Usage:       []string{"rsbx policy refresh"},
		Flags:       []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for policy refresh"}},
	}
}

func policyResetHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Remove all custom global rules and restore the default profile.",
			"Sandbox-scoped rules are kept. Confirmation is required unless --force is given.",
		},
		Usage: []string{"rsbx policy reset [flags]"},
		Flags: []commandFlagHelp{
			{Short: "f", Name: helpNameForce, Description: "remove custom global rules without confirmation"},
			{Short: "h", Name: helpCommand, Description: "help for policy reset"},
		},
	}
}

func policyApprovalHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Review and respond to pending approvals.",
			"Not implemented: approval-gated operations are unavailable, so no approvals can be pending.",
		},
		Usage: []string{"rsbx policy approval"},
		Flags: []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for policy approval"}},
	}
}

func policyMutateHelp(action string) commandHelp {
	return commandHelp{
		Description: []string{
			"Add or remove a network policy rule.",
			"",
			"The legacy grammar scopes the rule to SANDBOX. The network grammar targets the",
			"global policy when --sandbox is omitted.",
		},
		Usage: []string{
			"rsbx policy " + action + " SANDBOX CIDR[:PORT]",
			"rsbx policy " + action + " network [--sandbox NAME] CIDR[:PORT]|DOMAIN",
		},
		Examples: []string{
			"rsbx policy " + action + " my-sandbox 203.0.113.0/24",
			"rsbx policy " + action + " network --sandbox my-sandbox example.com",
		},
		Flags: []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for policy " + action}},
	}
}

func policyMutateNetworkHelp(action string) commandHelp {
	if action == "rm" {
		return policyRemoveNetworkHelp()
	}
	return commandHelp{
		Description: []string{
			"Add or remove a network policy rule.",
			"Flags may appear before, between or after arguments; use -- to end flag parsing.",
		},
		Usage: []string{"rsbx policy " + action + " network [flags] CIDR[:PORT]|DOMAIN"},
		Flags: []commandFlagHelp{
			{Short: "h", Name: helpCommand, Description: "help for policy " + action + " network"},
			{Name: helpNameMethod, Value: "strings", Description: "restrict the rule to these HTTP methods (comma list or repeats; ANY matches every method)"},
			{Name: "path", Value: helpValueString, Description: "restrict the rule to this HTTP path glob (** spans segments, * does not)"},
			{Name: "query", Value: "stringArray", Description: "require an HTTP query parameter name=glob (repeatable)"},
			{Name: helpNameSandbox, Value: helpValueString, Description: "scope the rule to one sandbox (global scope when omitted)"},
		},
	}
}

func policyRemoveNetworkHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Remove a network rule by rule ID, resource, or a positional target.",
			"",
			"--id takes the RULE_ID value shown by \"rsbx policy ls --wide\".",
			"--resource accepts one or more comma-separated resource values. The",
			"command resolves every selector before removing anything.",
			"Pass only one of --id, --resource, or a positional target.",
			"",
			"HTTP method/path/query selectors narrow a resource or positional",
			"match; --id cannot be combined with them.",
		},
		Usage: []string{"rsbx policy rm network [--sandbox SANDBOX] [flags]"},
		Examples: []string{
			"rsbx policy ls --wide",
			"rsbx policy rm network --resource api.example.com:443",
			"rsbx policy rm network --id rul_1234abcd",
			"rsbx policy rm network --sandbox my-sandbox --resource api.example.com",
		},
		Flags: []commandFlagHelp{
			{Short: "f", Name: helpNameForce, Description: "skip confirmation prompts"},
			{Short: "h", Name: helpCommand, Description: "help for policy rm network"},
			{Name: "id", Value: helpValueString, Description: "remove by rule ID"},
			{Name: helpNameMethod, Value: "strings", Description: "HTTP methods the removed rule must be conditioned on"},
			{Name: "path", Value: helpValueString, Description: "HTTP path glob the removed rule must be conditioned on"},
			{Name: "query", Value: "stringArray", Description: "HTTP query parameter name=glob condition"},
			{Name: "resource", Value: helpValueString, Description: "remove by resource value(s), comma-separated"},
			{Name: helpNameSandbox, Value: helpValueString, Description: "scope the removal to a specific sandbox"},
		},
	}
}

func policyCheckHelp() commandHelp {
	return commandHelp{
		Description: []string{"Evaluate a request against a sandbox's stored network rules."},
		Usage:       []string{"rsbx policy check SANDBOX IP PORT [PROTOCOL]"},
		Flags:       []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for policy check"}},
	}
}

func policyCheckNetworkHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Evaluate an IPv4[:PORT], IPv6[:PORT], domain[:PORT], or http(s) URL target.",
			"Bare targets without a port default to 443. Exit 0 when allowed, 1 when denied.",
		},
		Usage: []string{"rsbx policy check network [flags] TARGET"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for policy check network"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
			{Name: helpNameMethod, Value: helpValueString, Description: "HTTP method to evaluate (http(s) URL targets only)"},
			{Name: "protocol", Value: helpValueString, Description: "protocol to evaluate: tcp or udp (default tcp)"},
			{Name: helpNameSandbox, Value: helpValueString, Description: "scope the check to one sandbox"},
		},
	}
}

func policyCheckFilesystemHelp() commandHelp {
	return commandHelp{
		Description: []string{"Evaluate whether a guest path is readable or writable."},
		Usage:       []string{"rsbx policy check filesystem --sandbox NAME [flags] PATH"},
		Flags: []commandFlagHelp{
			{Short: "h", Name: helpCommand, Description: "help for policy check filesystem"},
			{Name: helpNameSandbox, Value: helpValueString, Description: "scope the check to one sandbox"},
			{Name: helpNameWrite, Description: "check write access instead of read"},
		},
	}
}

func policyInitHelp() commandHelp {
	return commandHelp{
		Description: []string{"Set the global default policy profile."},
		Usage:       []string{"rsbx policy init allow-all|balanced|deny-all"},
		Flags:       []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for policy init"}},
	}
}

func policyProfileHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Show the global default policy profile.",
			"",
			"Governance policy profiles are listed by \"rsbx policy profile ls\", which",
			"fails closed until the daemon exposes profile names.",
		},
		Usage: []string{"rsbx policy profile [ls]"},
		AvailableCommands: []commandSummary{
			{Name: "ls", Description: "List policy profiles (fails closed; see help)"},
		},
		Flags: []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for policy profile"}},
	}
}

func policyProfileListHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"List policy profiles available from remote governance policies.",
			"",
			"The daemon does not expose governance profile names or the policies attached",
			"to them, so this command fails closed instead of printing an incomplete list.",
			"Use \"rsbx policy profile\" to show the global default profile.",
		},
		Usage:    []string{"rsbx policy profile ls [flags]"},
		Aliases:  []string{"ls", "list"},
		Examples: []string{"rsbx policy profile ls", "rsbx policy profile ls --json"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for ls"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
			{Short: "q", Name: "quiet", Description: "only display profile names"},
		},
	}
}

func policyOrgHelp() commandHelp {
	return commandHelp{
		Description: []string{"Show the effective organization policy bundle without changing it."},
		Usage:       []string{"rsbx policy org [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for policy org"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
		},
	}
}

func resetHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Reset local sandboxes to a freshly-stopped state.",
			"",
			"Remove every sandbox owned by the connected daemon. Settings, images and the daemon",
			"state directory are not deleted. Confirmation requires a terminal and an empty",
			"answer cancels; --force skips confirmation.",
			"",
			"WARNING: this is destructive and cannot be undone.",
		},
		Usage: []string{"rsbx reset [flags]"},
		Examples: []string{
			"rsbx reset",
			"",
			"# Skip the confirmation prompt",
			"rsbx reset --force",
		},
		Flags: []commandFlagHelp{
			{Short: "f", Name: helpNameForce, Description: "Skip confirmation prompt"},
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for reset"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
		},
	}
}

func secretHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Manage stored secrets for sandbox environments: service secrets and registry credentials.",
			"",
			"SERVICE SECRETS (for example \"github\", \"anthropic\", \"openai\")",
			"  When a sandbox starts, the proxy uses stored secrets to authenticate API",
			"  requests on behalf of the agent. The secret is never exposed directly.",
			"  Scoped globally (shared across all sandboxes) or to a specific sandbox.",
			"",
			"REGISTRY SECRETS (for example \"ghcr.io\")",
			"  Used to pull private template images and kit artifacts before sandbox",
			"  creation. Registry credentials are host-only by default and are not injected",
			"  into sandboxes unless --all-sandboxes or --sandbox is set.",
		},
		Usage:   []string{"rsbx secret COMMAND"},
		Aliases: []string{"secret, secrets"},
		AvailableCommands: []commandSummary{
			{Name: commandImport, Description: "Import secrets detected in host environment variables"},
			{Name: "ls", Description: "List stored secrets"},
			{Name: "rm", Description: "Remove a secret"},
			{Name: commandSet, Description: "Create or update a secret"},
			{Name: "set-custom", Description: "(Experimental) Create or update a custom secret (unsupported)"},
		},
		Flags:  []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for secret"}},
		Footer: "Use \"rsbx secret COMMAND --help\" for more information about a command.",
	}
}

func secretSetHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Create a service secret or registry credential.",
			"An existing credential in the same scope is not replaced unless --force is passed.",
			"",
			"Available services: anthropic, copilot, cursor, devin, droid, github, google,",
			"groq, mistral, nebius, openai, openrouter, xai",
			"",
			"When SERVICE is omitted, choose it with the arrow keys and Enter. Press q or",
			"Escape to cancel. Values are stored in the host credential vault. For scripts,",
			"pass SERVICE explicitly and provide the value with --token or standard input.",
			"",
			"Registry credentials: use --registry to store a registry credential. Without",
			"--sandbox or --all-sandboxes, it is host-only and is not injected into sandboxes.",
			"Credentials are provided to the host broker, not guest env.",
			"Cross-host registry authentication endpoints are not supported yet.",
		},
		Usage: []string{
			"rsbx secret set [SERVICE] [flags]",
			"rsbx secret set --registry HOST --username USER [--password-stdin] [flags]",
		},
		Examples: []string{
			"rsbx secret set github",
			"rsbx secret set openai --sandbox my-sandbox",
			"rsbx secret set openai --oauth",
			"printf '%s' \"$GHCR_TOKEN\" | rsbx secret set --registry ghcr.io \\",
			"  --username USER --password-stdin --all-sandboxes",
		},
		Flags: []commandFlagHelp{
			{Name: "all-sandboxes", Description: "Enable brokered registry use in every sandbox"},
			{Name: commandName, Value: helpValueString, Description: "Run a host shell command to resolve a secret (can access host files)"},
			{Short: "f", Name: helpNameForce, Description: "Overwrite an existing secret or registry credential"},
			{Short: "h", Name: helpCommand, Description: "help for secret set"},
			{Name: "no-verify", Description: "Store a source without resolving it now"},
			{Name: "oauth", Description: "Sign in to the global OpenAI account on the host"},
			{Name: "password-stdin", Description: "Read registry password or token from stdin"},
			{Name: "ref", Value: helpValueString, Description: "Use a 1Password op:// reference or AWS Secrets Manager ARN"},
			{Name: helpNameRefresh, Value: helpValueString, Description: "Refresh source on-demand or after a duration (default: 55m)"},
			{Name: helpNameRegistry, Value: helpValueString, Description: "Registry hostname for pull credentials"},
			{Name: helpNameSandbox, Value: helpValueString, Description: "Scope the secret to one sandbox"},
			{Name: "show-error", Description: "Show provider stderr on initial verification failure (may contain secrets)"},
			{Short: "t", Name: "token", Value: helpValueString, Description: "Secret value (less secure: visible in shell history)"},
			{Name: "username", Value: helpValueString, Description: "Registry username"},
		},
	}
}

func secretRemoveHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Remove a service or registry credential. Removing a credential that is not",
			"stored prints one message and succeeds, so repeated cleanup is safe.",
		},
		Usage: []string{
			"rsbx secret rm [SERVICE] [flags]",
			"rsbx secret rm --registry HOST [flags]",
			"rsbx secret rm --all [flags]",
		},
		Aliases: []string{"rm, remove, delete, unset"},
		Examples: []string{
			"rsbx secret rm",
			"rsbx secret rm openai",
			"rsbx secret rm openai --sandbox my-sandbox",
			"rsbx secret rm openai --oauth",
			"rsbx secret rm --registry ghcr.io --all-sandboxes --force",
		},
		Flags: []commandFlagHelp{
			{Name: helpNameAll, Description: "Remove inventoried Rheic credentials across scopes"},
			{Name: "all-sandboxes", Description: "Remove the all-sandboxes registry credential (requires --registry)"},
			{Short: "f", Name: helpNameForce, Description: "Delete without confirmation prompt"},
			{Name: "global", Description: "Deprecated: remove global credentials"},
			{Short: "h", Name: helpCommand, Description: "help for secret rm"},
			{Name: "oauth", Description: "Remove host-side OpenAI OAuth credentials"},
			{Name: helpNameRegistry, Value: helpValueString, Description: "Registry hostname; without a scope flag removes host-only and all-sandboxes credentials"},
			{Name: helpNameSandbox, Value: helpValueString, Description: "Scope service or registry credentials to one sandbox"},
		},
	}
}

func secretListHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"List stored secrets across global and sandbox scopes. Secret values are never",
			"displayed. Use --global or --sandbox to limit the inventory, and --service to",
			"filter by provider.",
		},
		Usage:   []string{"rsbx secret ls [flags]"},
		Aliases: []string{helpAliasList},
		Examples: []string{
			"rsbx secret ls",
			"rsbx secret ls -g",
			"rsbx secret ls --sandbox my-sandbox",
			"rsbx secret ls --service github",
			"rsbx secret ls --json",
		},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatDescription},
			{Short: "g", Name: "global", Description: "Only list global secrets"},
			{Short: "h", Name: helpCommand, Description: "help for secret ls"},
			{Name: listFormatJSON, Description: helpJSONDescription},
			{Short: "q", Name: helpNameQuiet, Description: "Only display secret names"},
			{Name: helpNameSandbox, Value: helpValueString, Description: "Only list secrets scoped to one sandbox"},
			{Name: "service", Value: helpValueString, Description: "Filter by secret service name"},
		},
	}
}

func secretImportHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Copy supported host credential variables (such as OPENAI_API_KEY,",
			"ANTHROPIC_API_KEY and GH_TOKEN) into the shared secret store.",
			"",
			"Detected variables are shown one at a time with a Y/n prompt and a preview of",
			"the value's final four characters. Existing stored values are never replaced",
			"without --force:",
			"",
			"  - Without --force, importing an existing value fails with an error naming the",
			"    service and global scope.",
			"  - --all adds new values without prompts and leaves existing ones intact.",
			"  - --force saves every detected value, replacing existing entries too.",
			"",
			"A stored OpenAI OAuth session takes precedence over OPENAI_API_KEY.",
			"--dry-run never writes and shows only a last-four-character preview.",
		},
		Usage: []string{"rsbx secret import [SERVICE] [flags]"},
		Examples: []string{
			"# Walk every detected env var, prompting before each import",
			"rsbx secret import",
			"",
			"# Non-interactive: import everything detected without prompting",
			"rsbx secret import --all",
			"",
			"# Preview what would be imported without writing",
			"rsbx secret import --dry-run",
		},
		Flags: []commandFlagHelp{
			{Name: helpNameAll, Description: "Import every detected env var without prompting"},
			{Name: dryRunName, Description: "Show what would be imported without writing"},
			{Short: "f", Name: helpNameForce, Description: "Overwrite an existing stored entry without confirmation"},
			{Short: "h", Name: helpCommand, Description: "help for secret import"},
		},
	}
}

func secretCustomHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Docker sbx supports custom secrets by storing a placeholder in the sandbox and",
			"replacing it in matching outbound request headers. Rheic does not implement",
			"custom-secret storage or proxy substitution yet.",
			"",
			"Unsupported. This command will not store or inject a secret. Passing Docker sbx",
			"option families to Rheic currently fails closed.",
		},
		Usage: []string{"rsbx secret set-custom [flags]"},
		Flags: []commandFlagHelp{
			{Short: "h", Name: helpCommand, Description: "help for secret set-custom"},
		},
	}
}

func settingsHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"View and manage settings for Rheic Sandboxes.",
			"",
			"Settings live in ~/.config/rheic/settings.toml. The catalog lists the pinned",
			"Docker Sandboxes matrix; Rheic consumes the documented local subset and stores",
			"the rest as validated overrides.",
			"",
			"Machine output uses the sbx settings record: key, value, type, source, default,",
			"env_var (only when sbx defines the variable) and requires_restart (only when a",
			"daemon restart is needed). Unknown keys are rejected.",
		},
		Usage: []string{"rsbx settings COMMAND"},
		AvailableCommands: []commandSummary{
			{Name: "get", Description: "Get the value of a setting"},
			{Name: "ls", Description: "List settings"},
			{Name: commandSet, Description: "Set a setting override"},
			{Name: "unset", Description: "Remove a setting override"},
		},
		Flags:  []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for settings"}},
		Footer: "Use \"rsbx settings COMMAND --help\" for more information about a command.",
	}
}

func settingsListHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"List the full setting catalog and the effective source of each value.",
			"JSON and YAML records use sbx's field names and keep booleans and integers typed.",
		},
		Usage: []string{"rsbx settings ls [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for settings ls"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
		},
	}
}

func settingsGetHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Print one setting value or its full catalog record. --json and --format json",
			"emit the same typed record as settings ls; without them the scalar is printed.",
		},
		Usage: []string{"rsbx settings get KEY [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for settings get"},
			{Name: listFormatJSON, Description: "print the full setting record"},
		},
	}
}

func settingsSetHelp() commandHelp {
	return commandHelp{
		Description: []string{"Set a validated setting override in the host settings file."},
		Usage:       []string{"rsbx settings set KEY VALUE"},
		Flags:       []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for settings set"}},
	}
}

func settingsUnsetHelp() commandHelp {
	return commandHelp{
		Description: []string{"Remove a setting override and restore the built-in default."},
		Usage:       []string{"rsbx settings unset KEY"},
		Flags:       []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for settings unset"}},
	}
}

func templateHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Manage sandbox templates.",
			"",
			"Templates are local images captured from sandboxes with save or imported from",
			"archives with load. ls and inspect also list the built-in agent template images.",
			"Template management requires daemon template support (API 0.0.33 or newer).",
		},
		Usage: []string{"rsbx template COMMAND"},
		AvailableCommands: []commandSummary{
			{Name: "export", Description: "Write a docker-save archive of a template"},
			{Name: commandInspect, Description: "Show the pinned image and status of a template"},
			{Name: "load", Description: "Import a docker-save or OCI template archive"},
			{Name: "ls", Description: "List built-in agent template images"},
			{Name: "rm", Description: "Remove a recorded template"},
			{Name: "save", Description: "Capture a sandbox into a new template image"},
		},
		Flags:  []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for template"}},
		Footer: "Use \"rsbx template COMMAND --help\" for more information about a command.",
	}
}

func templateListHelp() commandHelp {
	return commandHelp{
		Description: []string{"List built-in agent template images."},
		Usage:       []string{"rsbx template ls [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for template ls"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
		},
	}
}

func templateInspectHelp() commandHelp {
	return commandHelp{
		Description: []string{"Show the pinned image, command and status for one template."},
		Usage:       []string{"rsbx template inspect NAME [flags]"},
		Flags: []commandFlagHelp{
			{Short: "h", Name: helpCommand, Description: "help for template inspect"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
		},
	}
}

func kitHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Manage local Rheic kits.",
			"",
			"Supports the Docker Kits v2 sandbox subset and Docker kit v3 descriptors",
			"(offline inspection only; no kit builder is implemented). Kits are unsigned",
			"local inputs; remote OCI kits, mixins, signatures and MCP allowlists are not",
			"implemented yet.",
		},
		Usage: []string{"rsbx kit COMMAND"},
		AvailableCommands: []commandSummary{
			{Name: commandInspect, Description: "Show kit artifact details"},
			{Name: "ls", Description: "List local .yaml kits"},
		},
		Flags:  []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for kit"}},
		Footer: "Use \"rsbx kit COMMAND --help\" for more information about a command.",
	}
}

func kitInspectHelp() commandHelp {
	return commandHelp{
		Description: []string{"Validate and print a local kit definition."},
		Usage:       []string{"rsbx kit inspect FILE_OR_DIR [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for kit inspect"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
		},
	}
}

func kitListHelp() commandHelp {
	return commandHelp{
		Description: []string{"List local .yaml kit files in DIR (default: current directory)."},
		Usage:       []string{"rsbx kit ls [DIR]"},
		Flags:       []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for kit ls"}},
	}
}

func tuiHelp() commandHelp {
	return commandHelp{
		Description: []string{"Open the interactive RHEIC sandbox dashboard."},
		Usage:       []string{"rsbx tui [flags]"},
		Examples:    []string{"rsbx tui"},
		Flags: []commandFlagHelp{
			{Short: "h", Name: helpCommand, Description: "help for tui"},
			{Name: helpNameRefresh, Value: "duration", Description: "dashboard refresh interval (default 5s)"},
		},
	}
}

func setupHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"EXPERIMENTAL: this command may change or be removed in future releases.",
			"",
			"Check whether this host has the components needed by local Rheic sandboxes.",
			"",
			"The check is read-only: it never installs software, changes settings, writes",
			"files, or starts a VM. Files being present does not prove a sandbox can boot.",
			"",
			"Checks: platform, daemon socket, runtime assets, binaries and the optional",
			"Docker CLI. Exit status is non-zero only when a required host component is",
			"missing.",
		},
		Usage: []string{"rsbx setup [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for setup"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
		},
	}
}

func skillsHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Manage skills available to agents in Rheic sandboxes.",
			"",
			"Experimental host-side agent skills store. Rheic keeps imported skills in its",
			"own config directory, never inside a sandbox workspace or Docker state.",
			"",
			"Import requires PATH to be a real directory containing SKILL.md with YAML",
			"frontmatter fields \"name\" and \"description\". Symlinks, special files, unsafe",
			"names and oversized trees are rejected. Re-importing identical content is a",
			"no-op; replacing changed content requires --force.",
		},
		Usage: []string{"rsbx skills COMMAND"},
		AvailableCommands: []commandSummary{
			{Name: "add, a", Description: "Add skills from a Git repository"},
			{Name: "ls, list", Description: "List skills imported by Rheic"},
			{Name: commandImport, Description: "Validate and import a local skill directory"},
			{Name: "rm, remove", Description: "Remove a skill imported by Rheic"},
			{Name: "update, upgrade", Description: "Update skills added from repositories"},
		},
		Flags:  []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for skills"}},
		Footer: "Use \"rsbx skills COMMAND --help\" for more information about a command.",
	}
}

const helpExperimentalLine = "EXPERIMENTAL: this command may change or be removed in future releases."

func skillsAddHelp() commandHelp {
	return commandHelp{
		Description: []string{
			helpExperimentalLine,
			"",
			"Install skills from a Git repository for use in Rheic sandboxes. The",
			"repository must contain one or more valid SKILL.md files.",
			"",
			"All discovered skills are installed when --skill is omitted. Use --skill one",
			"or more times, or pass a comma-separated list, to install only named skills.",
			"Replacing an installed skill with different content requires --force; identical",
			"skills are left unchanged. Repositories with a credential in the URL are refused.",
			"",
			"The repository can be specified as a Git URL or as GitHub owner/repository",
			"shorthand. Skills installed with this command can later be refreshed with",
			"'rsbx skills update'.",
		},
		Usage:   []string{"rsbx skills add REPOSITORY [flags]"},
		Aliases: []string{"add, a"},
		Examples: []string{
			"rsbx skills add https://github.com/anthropics/skills --skill frontend-design",
			"rsbx skills add anthropics/skills --skill frontend-design --skill pdf",
			"rsbx skills add https://github.com/anthropics/skills --force",
		},
		Flags: []commandFlagHelp{
			{Short: "f", Name: helpNameForce, Description: "Overwrite existing skills without prompting"},
			{Short: "h", Name: helpCommand, Description: "help for add"},
			{Short: "s", Name: "skill", Value: helpValueName, Description: "Add only the named skill (repeatable or comma-separated)"},
		},
	}
}

func skillsUpdateHelp() commandHelp {
	return commandHelp{
		Description: []string{
			helpExperimentalLine,
			"",
			"Download the latest versions of skills installed with 'rsbx skills add'.",
			"",
			"With no names, every skill added from a repository is updated. Specify one or",
			"more names to update only those skills. Skills installed with 'rsbx skills",
			"import' must be added from a repository before they can be updated.",
		},
		Usage:   []string{"rsbx skills update [SKILL...] [flags]"},
		Aliases: []string{"update, upgrade"},
		Examples: []string{
			"# Update every skill added from a repository",
			"rsbx skills update",
			"",
			"# Update one skill",
			"rsbx skills update my-skill",
		},
		Flags: []commandFlagHelp{
			{Short: "h", Name: helpCommand, Description: "help for update"},
		},
	}
}

func skillsListHelp() commandHelp {
	return commandHelp{
		Description: []string{"List skills imported by Rheic."},
		Usage:       []string{"rsbx skills ls [flags]"},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: helpFormatLowerDescription},
			{Short: "h", Name: helpCommand, Description: "help for skills ls"},
			{Name: listFormatJSON, Description: helpJSONLowerDescription},
			{Short: "q", Name: helpNameQuiet, Description: "only display skill names"},
		},
	}
}

func skillsImportHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Import a local skill directory into Rheic's host-side skills store.",
			"Without PATH, import from supported host directories in priority order.",
			"Use --dry-run without PATH to preview candidates in supported host directories.",
			"A skill-directory link requires --allow-link NAME=ABSOLUTE_TARGET. --force",
			"does not approve links; the target must be a canonical real directory.",
			"PATH must be a real directory with a SKILL.md file. SKILL.md requires YAML",
			"frontmatter with \"name\" and \"description\" fields.",
			"",
			"Other symlinks, special files, oversized files and oversized trees are rejected.",
			"Identical re-imports are no-ops. Use --force only to replace skill content that",
			"Rheic already imported; unmanaged directories are never overwritten.",
		},
		Usage: []string{"rsbx skills import [flags] [PATH]", "rsbx skills import --dry-run"},
		Flags: []commandFlagHelp{
			{Name: dryRunName, Description: "preview host skills without importing them"},
			{Name: "allow-link", Value: "NAME=ABSOLUTE_TARGET", Description: "approve one exact link target (repeatable)"},
			{Short: "f", Name: helpNameForce, Description: "replace skill content previously imported by Rheic"},
			{Short: "h", Name: helpCommand, Description: "help for skills import"},
		},
	}
}

func skillsRemoveHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Remove one skill that Rheic imported.",
			"Directories in the skills store that are not recorded in Rheic's registry are",
			"never removed. Without --force, an interactive terminal confirmation is required.",
		},
		Usage: []string{"rsbx skills rm [flags] NAME"},
		Flags: []commandFlagHelp{
			{Short: "f", Name: helpNameForce, Description: "skip confirmation"},
			{Short: "h", Name: helpCommand, Description: "help for skills rm"},
		},
	}
}

func completionHelp() commandHelp {
	return commandHelp{
		Description: []string{
			"Generate the autocompletion script for rsbx for the specified shell.",
			"See each shell's generated script for details on how to use it.",
		},
		Usage: []string{"rsbx completion COMMAND"},
		AvailableCommands: []commandSummary{
			{Name: helpNameBash, Description: "Generate the autocompletion script for bash"},
			{Name: helpNameFish, Description: "Generate the autocompletion script for fish"},
			{Name: helpNamePowershell, Description: "Generate the autocompletion script for powershell"},
			{Name: helpNameZsh, Description: "Generate the autocompletion script for zsh"},
		},
		Flags:  []commandFlagHelp{{Short: "h", Name: helpCommand, Description: "help for completion"}},
		Footer: "Use \"rsbx completion COMMAND --help\" for more information about a command.",
	}
}

func versionHelp() commandHelp {
	return commandHelp{
		Description: []string{"Show Rheic Sandboxes version information."},
		Usage:       []string{"rsbx version [flags]"},
		Examples: []string{
			"rsbx version",
			"",
			"# Include daemon and build details",
			"rsbx version --debug",
		},
		Flags: []commandFlagHelp{
			{Name: helpNameFormat, Value: helpValueString, Description: "Output format: table, json or yaml"},
			{Short: "h", Name: helpCommand, Description: "help for version"},
			{Name: listFormatJSON, Description: helpJSONDescription},
		},
	}
}
