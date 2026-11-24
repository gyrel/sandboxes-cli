package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rheic/sandboxes-cli/internal/envfile"
)

const previewDefault = "default"

type repeatedStringFlag []string

func (f *repeatedStringFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *repeatedStringFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func (r *Runner) environment(ctx context.Context, args []string) int {
	args, code, done := r.prepareFamilyArgs(envCommand, args)
	if done {
		return code
	}
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		return r.showCommandHelp(envHelp())
	}
	switch args[0] {
	case "plan":
		return r.environmentPlan(args[1:])
	case commandCreate:
		return r.environmentCreate(ctx, args[1:])
	case commandExec:
		return r.environmentExec(ctx, args[1:])
	case commandRun:
		return r.environmentRun(ctx, args[1:])
	case "rm":
		return r.environmentRemove(ctx, args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "rsbx env %s: unsupported\n", args[0])
		return 1
	}
}

func (r *Runner) environmentPlan(args []string) int {
	fs := r.newFlagSet("env plan")
	fs.SetOutput(io.Discard)
	name := fs.String("name", "", "override the environment sandbox name")
	skipHostCommands := fs.Bool(helpNameSkipHost, false, "plan without host lifecycle commands and command-backed MCP servers")
	var envArguments, envArgumentFiles repeatedStringFlag
	fs.Var(&envArguments, "env-arg", "value for an argument declared in sbxenv.yaml (repeatable)")
	fs.Var(&envArgumentFiles, "env-args-file", "file of name=value environment arguments (repeatable)")
	fs.Usage = func() { r.showCommandHelp(envPlanHelp()) }
	valueFlags := map[string]bool{nameFlag: true, envArgFlag: true, envArgsFileFlag: true}
	if err := fs.Parse(reorderFlagArgs(args, valueFlags)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("env plan", err)
	}
	plan, err := loadEnvironmentPlan(fs.Args(), envfile.ArgumentOverrides{Files: envArgumentFiles, Values: envArguments})
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env plan: %s\n", err)
		return 1
	}
	_ = skipHostCommands
	if err := applyEnvironmentName(&plan, *name); err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx env plan: %s\n", err)
		return 1
	}
	var out strings.Builder
	fmt.Fprintln(&out, "Static preview (no changes applied; daemon state not queried)")
	fmt.Fprintf(&out, "Name: %s\nAgent: %s\n", displayPreviewValue(plan.Name, plan.NameRedacted), displayPreviewValue(plan.Agent, plan.AgentRedacted))
	fmt.Fprintf(&out, "Workspace: %s\n", displayPreviewPath(plan.Workspace, plan.WorkspaceRedacted))
	fmt.Fprintf(&out, "Additional workspaces: %d\n", len(plan.AdditionalWorkspaces))
	for _, workspace := range plan.AdditionalWorkspaces {
		mode := "read-write"
		if workspace.ReadOnly {
			mode = "read-only"
		}
		fmt.Fprintf(&out, "  %s (%s)\n", displayPreviewPath(workspace.Path, workspace.Redacted), mode)
	}
	writePortPreview(&out, plan.Ports)
	writeRedactedNames(&out, "Environment keys", plan.EnvironmentKeys)
	writeRedactedNames(&out, "Environment arguments", plan.ArgumentNames)
	if plan.CPUs != nil {
		if plan.CPUsRedacted {
			fmt.Fprintln(&out, "CPUs: <redacted>")
		} else {
			fmt.Fprintf(&out, "CPUs: %d\n", *plan.CPUs)
		}
	}
	if plan.Memory != "" {
		fmt.Fprintf(&out, "Memory: %s\n", displayPreviewValue(plan.Memory, plan.MemoryRedacted))
	}
	if _, err := fmt.Fprint(r.Out, out.String()); err != nil {
		r.error(errors.New("write environment plan failed"))
		return 1
	}
	return 0
}

func writePortPreview(out *strings.Builder, ports []envfile.Port) {
	fmt.Fprintf(out, "Ports: %d\n", len(ports))
	for _, port := range ports {
		if port.Redacted {
			fmt.Fprintln(out, "  <redacted>")
			continue
		}
		host := "ephemeral"
		if port.Host != nil {
			host = fmt.Sprintf("%d", *port.Host)
		}
		protocol := port.Protocol
		if protocol == "" {
			protocol = previewDefault
		}
		hostIP := port.HostIP
		if hostIP == "" {
			hostIP = previewDefault
		}
		fmt.Fprintf(out, "  sandbox %d -> host %s (%s, hostIP %s)\n", port.Sandbox, host, protocol, hostIP)
	}
}

func writeRedactedNames(out *strings.Builder, label string, names []string) {
	fmt.Fprintf(out, "%s: %d\n", label, len(names))
	for _, name := range names {
		fmt.Fprintf(out, "  %s=<redacted>\n", name)
	}
}

func applyEnvironmentName(plan *envfile.Plan, name string) error {
	if name == "" {
		return nil
	}
	if err := envfile.ValidateName(name); err != nil {
		return err
	}
	plan.Name = name
	plan.NameRedacted = false
	return nil
}

func loadEnvironmentPlan(paths []string, overrides envfile.ArgumentOverrides) (envfile.Plan, error) {
	if len(paths) > 0 {
		return envfile.LoadWithArguments(paths, overrides)
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return envfile.Plan{}, errors.New("resolve default environment paths")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return envfile.Plan{}, errors.New("resolve default environment paths")
	}
	return envfile.LoadDefaultWithArguments(homeDir, workingDir, overrides)
}

func displayValue(value string) string {
	if value == "" {
		return "(unset)"
	}
	return value
}

func displayPreviewValue(value string, redacted bool) string {
	if redacted {
		return "<redacted>"
	}
	return displayValue(value)
}

func displayPreviewPath(value string, redacted bool) string {
	if redacted {
		return "<redacted>"
	}
	return displayPath(value)
}

func displayPath(value string) string {
	if value == "" {
		return "(unset)"
	}
	return fmt.Sprintf("%q", value)
}
