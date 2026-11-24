package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	sdk "github.com/rheic/sandboxes-go-sdk"

	"github.com/rheic/sandboxes-cli/internal/kit"
)

const kitUsage = `Usage: rsbx kit COMMAND

Manage local Rheic kits, the supported Docker Kits v2 sandbox subset and
Docker kit v3 descriptors (offline inspection only; no kit builder is
implemented). Kits are unsigned local inputs; remote OCI kits, mixins,
signatures and MCP allowlists are not implemented yet.

Commands:
  inspect FILE_OR_DIR [--format table|json|yaml]   validate and print a kit
  ls [DIR]                                  list local .yaml kits
  pack DIRECTORY [--output PATH]            package a kit directory as a .zip
  validate REFERENCE [--offline]            validate a kit directory or .zip
`

const kitInspectUsage = `usage: rsbx kit inspect FILE_OR_DIR [--format table|json|yaml] [--json]

Validate and print a local kit definition.
`

const kitListUsage = `usage: rsbx kit ls [DIR]

List local .yaml kit files in DIR (default: current directory).
`

func (r *Runner) kit(args []string) int {
	args, code, done := r.prepareFamilyArgs(kitCommand, args)
	if done {
		return code
	}
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, kitUsage)
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		return r.showCommandHelp(kitHelp())
	case commandInspect:
		return r.kitInspect(args[1:])
	case "ls":
		return r.kitList(args[1:])
	case commandValidate:
		return r.kitValidate(args[1:])
	case commandPack:
		return r.kitPack(args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "rsbx kit: unknown subcommand %q\n", args[0])
		return 2
	}
}

func (r *Runner) kitInspect(args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		return r.showCommandHelp(kitInspectHelp())
	}
	args = reorderFlagArgs(args, map[string]bool{formatFlag: true})
	fs := r.newFlagSet("kit inspect")
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("kit inspect", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, kitInspectUsage)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	doc, err := kit.Load(fs.Arg(0))
	if err != nil {
		r.error(err)
		return 1
	}
	if doc.V3 != nil {
		return r.printV3Kit(doc.V3, selected)
	}
	switch selected {
	case listFormatTable:
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "NAME\tAGENT\tIMAGE\tPROFILE\tMOUNTS")
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", doc.Metadata.Name, doc.Spec.Agent, doc.Spec.Image, doc.Spec.PolicyProfile, strings.Join(doc.Paths(), ","))
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(doc)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(doc); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}

func (r *Runner) printV3Kit(doc *kit.V3Descriptor, selected string) int {
	switch selected {
	case listFormatTable:
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "KIND\tNAME\tVERSION\tCAPABILITIES")
		label := doc.DisplayName
		if label == "" {
			label = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", doc.Kind, label, doc.Version, len(doc.Capabilities))
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(doc)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(doc); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}

func (r *Runner) kitList(args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		return r.showCommandHelp(kitListHelp())
	}
	if len(args) > 1 {
		_, _ = fmt.Fprint(r.Err, kitListUsage)
		return 2
	}
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		r.error(err)
		return 1
	}
	tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "FILE\tNAME\tAGENT\tPROFILE")
	found := 0
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}
		doc, err := kit.Load(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		found++
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", entry.Name(), doc.Metadata.Name, doc.Spec.Agent, doc.Spec.PolicyProfile)
	}
	if err := tw.Flush(); err != nil {
		r.error(err)
		return 1
	}
	if found == 0 {
		_, _ = fmt.Fprintln(r.Out, "No local kits found")
	}
	return 0
}

// kitInputs carries the kit flags that applyKit resolves against the kit.
type kitInputs struct {
	arguments map[string]string
	envFiles  []string
}

// kitArgumentsFromFlags collects --kit-arg and --kit-args-file values for one
// kit reference. Arguments without a kit are refused so they are never dropped.
func kitArgumentsFromFlags(kitRef string, values, files []string) (map[string]string, error) {
	if kitRef == "" {
		if len(values) > 0 || len(files) > 0 {
			return nil, errors.New("--kit-arg and --kit-args-file require --kit")
		}
		return map[string]string{}, nil
	}
	return kit.CollectArguments(files, values)
}

func applyKit(ctx context.Context, path string, agent, image, profile *string, paths, env *[]string, oauthCredentials *[]sdk.OAuthCredential, inputs kitInputs) error {
	doc, err := kit.Load(path)
	if err != nil {
		return err
	}
	if doc.V3 != nil && v3NeedsBuilder(doc.V3) {
		return errors.New("kit v3 descriptors require a kit builder; building and applying v3 kits is not implemented")
	}
	kitName, err := kitNameForArguments(path)
	if err != nil {
		return err
	}
	values, violations := kit.ResolveArgumentValues(doc, kitName, "", inputs.arguments)
	if len(violations) > 0 {
		return &kit.ViolationError{Violations: violations}
	}
	if doc.V3 != nil {
		return applyV3KitArguments(doc, values, env, inputs.envFiles)
	}
	for _, value := range []struct {
		label   string
		target  *string
		fromKit string
	}{
		{"agent", agent, doc.Spec.Agent}, {"image", image, doc.Spec.Image}, {"policy profile", profile, doc.Spec.PolicyProfile},
	} {
		if err := mergeKitValue(value.label, value.target, value.fromKit); err != nil {
			return err
		}
	}
	if seed := doc.Spec.Workspace.Seed; seed != "" {
		resolved, err := kit.ResolveSeed(ctx, seed, kit.SeedCacheRoot())
		if err != nil {
			return err
		}
		*paths = append([]string{resolved}, *paths...)
	}
	*paths = append(*paths, doc.Paths()...)
	converted, err := convertOAuthCredentials(doc.Spec.Credentials)
	if err != nil {
		return err
	}
	*oauthCredentials = append(*oauthCredentials, converted...)
	return mergeOAuthEnvironment(doc, env)
}

// v3NeedsBuilder reports whether a v3 descriptor carries content or dependency
// declarations that only a kit builder can apply. Provides claims tools the kit
// installs, so applying its args without the builder would deliver a sandbox
// that silently lacks them.
func v3NeedsBuilder(doc *kit.V3Descriptor) bool {
	return doc.NeedsBuild || len(doc.Capabilities) > 0 || len(doc.Kits) > 0 ||
		len(doc.Provides) > 0 ||
		len(doc.Requires) > 0 || len(doc.Integrates) > 0 || len(doc.Conflicts) > 0
}

// kitNameForArguments returns the name that kit.name=value keys match. It is
// the directory name, or the file name without its extension, as kit validate
// reports it.
func kitNameForArguments(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve kit reference: %w", err)
	}
	info, err := os.Stat(abs) // #nosec G304,G703 -- user-selected kit reference from the CLI flag; read-only stat of the chosen path (AGENTS 8 workspace-trust grammar)
	if err != nil {
		return "", fmt.Errorf("inspect kit reference: %w", err)
	}
	name := filepath.Base(abs)
	if !info.IsDir() {
		name = strings.TrimSuffix(name, filepath.Ext(name))
	}
	return name, nil
}

// applyV3KitArguments delivers the resolved arguments of a builder-free v3 kit
// through the same environment list that --env feeds. A value that would
// silently replace an explicit --env or --env-file entry is refused.
func applyV3KitArguments(doc kit.Kit, values map[string]string, env *[]string, envFiles []string) error {
	entries, err := kit.ArgumentEnvironment(doc, values)
	if err != nil {
		return err
	}
	taken := make(map[string]struct{}, len(*env))
	for _, entry := range *env {
		key, _, _ := strings.Cut(entry, "=")
		taken[key] = struct{}{}
	}
	for _, file := range envFiles {
		lines, err := readExecEnvFile(file)
		if err != nil {
			return err
		}
		for _, line := range lines {
			key, _, _ := strings.Cut(line, "=")
			taken[key] = struct{}{}
		}
	}
	for _, entry := range entries {
		key, _, _ := strings.Cut(entry, "=")
		if _, clash := taken[key]; clash {
			return fmt.Errorf("environment variable %s is set by a kit argument and by --env or --env-file", key)
		}
	}
	*env = append(*env, entries...)
	return nil
}

func mergeKitValue(label string, target *string, fromKit string) error {
	if *target != "" && fromKit != "" && *target != fromKit {
		return fmt.Errorf("kit %s %q conflicts with requested %q", label, fromKit, *target)
	}
	if *target == "" {
		*target = fromKit
	}
	return nil
}

func convertOAuthCredentials(credentials []kit.Credential) ([]sdk.OAuthCredential, error) {
	converted := make([]sdk.OAuthCredential, 0, len(credentials))
	for _, credential := range credentials {
		oauth := credential.OAuth
		if oauth == nil {
			continue
		}
		// OpenAI OAuth uses the daemon's separately configured provider adapter;
		// this declaration cannot replace its issuer or endpoint policy.
		if credential.Service == openAIService {
			continue
		}
		var tokenEndpoint *sdk.OAuthTokenEndpoint
		if oauth.TokenEndpoint != nil {
			tokenEndpoint = &sdk.OAuthTokenEndpoint{Host: oauth.TokenEndpoint.Host, Path: oauth.TokenEndpoint.Path}
		}
		var sentinels *sdk.OAuthSentinels
		if oauth.Sentinels != nil {
			sentinels = &sdk.OAuthSentinels{AccessToken: oauth.Sentinels.AccessToken, RefreshToken: oauth.Sentinels.RefreshToken}
		}
		var credentialFile *sdk.OAuthCredentialFile
		if oauth.CredentialFile != nil {
			structure := ""
			if len(oauth.CredentialFile.Structure) > 0 {
				encoded, err := json.Marshal(oauth.CredentialFile.Structure)
				if err != nil {
					return nil, fmt.Errorf("encode kit OAuth credential structure: %w", err)
				}
				structure = string(encoded)
			}
			credentialFile = &sdk.OAuthCredentialFile{Path: oauth.CredentialFile.Path, StructureJSON: structure, Template: oauth.CredentialFile.Template}
		}
		var responseFields *sdk.OAuthResponseFields
		if oauth.ResponseFields != nil {
			fields := oauth.ResponseFields
			responseFields = &sdk.OAuthResponseFields{AccessToken: fields.AccessToken, RefreshToken: fields.RefreshToken, ExpiresIn: fields.ExpiresIn, Scope: fields.Scope, IDToken: fields.IDToken}
		}
		converted = append(converted, sdk.OAuthCredential{Service: credential.Service,
			TokenEndpoint:  tokenEndpoint,
			ResourceHosts:  append([]string(nil), oauth.ResourceHosts...),
			Sentinels:      sentinels,
			CredentialFile: credentialFile,
			ResponseFields: responseFields,
			Passthrough:    oauth.Passthrough, SkipIfEnv: append([]string(nil), oauth.SkipIfEnv...)})
	}
	return converted, nil
}

func mergeOAuthEnvironment(doc kit.Kit, env *[]string) error {
	for _, credentialEnv := range doc.OAuthEnvironment() {
		credentialKey, _, _ := strings.Cut(credentialEnv, "=")
		baseURLKey := ""
		if credentialKey == openAIAPIKeyEnv {
			baseURLKey = openAIBaseURLEnv
		}
		for _, existing := range *env {
			key, _, _ := strings.Cut(existing, "=")
			if key == credentialKey || (baseURLKey != "" && key == baseURLKey) {
				return fmt.Errorf("kit OAuth credential conflicts with explicit %s", key)
			}
		}
		*env = append(*env, credentialEnv)
	}
	return nil
}
