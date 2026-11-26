package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	sdk "github.com/gyrel/sandboxes-go-sdk"

	"github.com/gyrel/sandboxes-cli/internal/kit"
)

const (
	commandValidate    = "validate"
	commandPack        = "pack"
	kitArgFlag         = "--kit-arg"
	kitArgsFileFlag    = "--kit-args-file"
	kitOutputFlag      = "--output"
	kitOutputShortFlag = "-o"
)

const kitValidateUsage = `usage: rsbx kit validate REFERENCE [--kit-arg NAME=VALUE] [--kit-args-file FILE] [--offline]

Validate a local kit directory or ZIP file.
`

const kitPackUsage = `usage: rsbx kit pack DIRECTORY [--output PATH]

Validate a kit directory and package it as a ZIP file.
`

type kitValidateOutput struct {
	Name          string `json:"name" yaml:"name"`
	Kind          string `json:"kind" yaml:"kind"`
	Valid         bool   `json:"valid" yaml:"valid"`
	PolicyChecked bool   `json:"policyChecked" yaml:"policyChecked"`
}

func (r *Runner) kitValidate(args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		return r.showCommandHelp(kitValidateHelp())
	}
	args = reorderFlagArgs(args, map[string]bool{formatFlag: true, kitArgFlag: true, kitArgsFileFlag: true})
	fs := r.newFlagSet("kit validate")
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	var kitArgs, kitArgFiles repeatedStringFlag
	fs.Var(&kitArgs, "kit-arg", "value for an argument the kit declares, as name=value or kit.name=value (can be repeated)")
	fs.Var(&kitArgFiles, "kit-args-file", "file of name=value kit arguments (can be repeated); --kit-arg overrides")
	offline := fs.Bool("offline", false, "skip the daemon-backed kit policy check; local directory or ZIP references only")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("kit validate", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, kitValidateUsage)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	reference := fs.Arg(0)
	if kit.IsGitReference(reference) {
		r.error(errors.New("kit validate git references are not implemented yet"))
		return 1
	}
	arguments, err := kit.CollectArguments(kitArgFiles, kitArgs)
	if err != nil {
		return r.commandError("kit validate", err.Error())
	}
	result, err := kit.Validate(reference, arguments)
	if err != nil {
		r.error(err)
		return 1
	}
	if len(result.Violations) > 0 {
		return r.kitViolations("kit validate", result.Violations)
	}
	if *offline {
		return r.printKitValidated(result, selected, false)
	}
	return r.kitPolicyValidate(reference, result, selected)
}

func (r *Runner) kitPolicyValidate(reference string, result kit.Result, selected string) int {
	sourceKind := sdk.KitSourceKindDirectory
	if strings.EqualFold(filepath.Ext(reference), ".zip") {
		sourceKind = sdk.KitSourceKindZip
	}

	client, err := r.client()
	if err != nil {
		return r.kitPolicyDaemonError(reference, err)
	}
	defer func() { _ = client.Close() }()

	check, err := sdk.KitPolicy(client).CheckKit(context.Background(), sdk.KitCheckRequest{
		SourceKind:       sourceKind,
		SourceRef:        reference,
		SignaturePresent: false,
	})
	if err != nil {
		return r.kitPolicyDaemonError(reference, err)
	}
	if !check.Allowed {
		return r.kitPolicyDenied(check)
	}
	return r.printKitValidated(result, selected, true)
}

// kitPolicyDenied prints a daemon-provided denial without claiming success.
func (r *Runner) kitPolicyDenied(check sdk.KitCheck) int {
	message := strings.TrimSpace(check.Message)
	if message == "" {
		message = string(check.Reason)
	}
	if message == "" {
		message = "kit policy denied"
	}
	_, _ = fmt.Fprintf(r.Err, "error: %s\n", sanitizeTerminalText(message))
	settings := check.CheckedSettings
	hint := "rsbx settings"
	if len(settings) > 0 {
		hint = "rsbx settings " + strings.Join(settings, ", ")
	}
	_, _ = fmt.Fprintf(r.Err, "  try: %s\n", sanitizeTerminalText(hint))
	return 1
}

// kitPolicyDaemonError fails closed when the daemon cannot be reached or the
// client is version-gated; it never falls back to --offline semantics.
func (r *Runner) kitPolicyDaemonError(reference string, err error) int {
	_, _ = fmt.Fprintf(r.Err, "error: policy could not be checked: %s\n  try: rsbx kit validate --offline %s\n", sanitizeTerminalText(err.Error()), sanitizeTerminalText(reference))
	return 1
}

func (r *Runner) printKitValidated(result kit.Result, format string, policyChecked bool) int {
	out := kitValidateOutput{Name: result.Name, Kind: result.Kind, Valid: true, PolicyChecked: policyChecked}
	switch format {
	case listFormatTable:
		if policyChecked {
			_, _ = fmt.Fprintf(r.Out, "Validated kit %s (policy: daemon-checked)\n", sanitizeTerminalText(out.Name))
		} else {
			_, _ = fmt.Fprintf(r.Out, "Validated kit %s (offline: daemon kit policy not checked)\n", sanitizeTerminalText(out.Name))
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(out)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(out); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}

func (r *Runner) kitViolations(cmdPath string, violations []kit.Violation) int {
	for _, violation := range violations {
		_, _ = fmt.Fprintf(r.Err, "error: %s\n", sanitizeTerminalText(violation.String()))
	}
	_, _ = fmt.Fprintf(r.Err, "  try: rsbx %s--help\n", commandHintPath(cmdPath))
	return 1
}

func (r *Runner) kitPack(args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		return r.showCommandHelp(kitPackHelp())
	}
	args = reorderFlagArgs(args, map[string]bool{kitOutputFlag: true, kitOutputShortFlag: true})
	fs := r.newFlagSet("kit pack")
	fs.SetOutput(io.Discard)
	var output string
	fs.StringVar(&output, "output", "", "output file path; must end in .zip (default: <name>.zip)")
	fs.StringVar(&output, "o", "", "output file path; must end in .zip (default: <name>.zip)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("kit pack", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, kitPackUsage)
		return 2
	}
	if output != "" && !strings.HasSuffix(output, ".zip") {
		_, _ = fmt.Fprint(r.Err, "error: kit pack output must end in .zip\n  try: rsbx kit pack --help\n")
		return 2
	}
	packed, err := kit.Pack(fs.Arg(0), output)
	if err != nil {
		var invalid *kit.ViolationError
		if errors.As(err, &invalid) {
			return r.kitViolations("kit pack", invalid.Violations)
		}
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Packed kit %s to %s\n", sanitizeTerminalText(packed.Name), sanitizeTerminalText(packed.Output))
	return 0
}
