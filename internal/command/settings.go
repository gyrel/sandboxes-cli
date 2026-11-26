package command

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"github.com/gyrel/sandboxes-cli/internal/settings"
)

const (
	// settingsUsage references the legacy-compat ~/.config/rheic directory,
	// retained so existing settings files keep loading without a migration.
	settingsUsage = `Usage: rsbx settings COMMAND

View and manage host settings in ~/.config/rheic/settings.toml. The catalog
lists the pinned Docker Sandboxes matrix; Gyrel consumes the documented
local subset and stores the rest as validated overrides.

Commands:
  ls [--format table|json|yaml]   list the full catalog and effective source
  get KEY [--json]                print one value or its full record
  set KEY VALUE                   set an override (type-validated)
  unset KEY                       remove an override

Machine output uses the sbx settings record: key, value, type, source, default,
env_var (only when sbx defines the variable) and requires_restart (only when a
daemon restart is needed). value and default keep their JSON type: booleans,
integers, objects/arrays for json settings, and strings otherwise.

Local runtime keys: dns.upstream (restart required), policy.profile,
defaults.cpus, defaults.memory_mib, sandbox.disk.dockerVolume,
mcp.remote.allowedHosts (restart required).
Unknown keys are rejected.
`
	settingsListUsage = `usage: rsbx settings ls [--format table|json|yaml] [--json]

List the full setting catalog and the effective source of each value. JSON and
YAML records use sbx's field names and keep booleans and integers typed.
`
	settingsGetUsage = `usage: rsbx settings get KEY [--json] [--format table|json|yaml]

Print one setting value or its full catalog record. --json and --format json
emit the same typed record as settings ls; without them the scalar is printed.
`
	settingsSetUsage = `usage: rsbx settings set KEY VALUE [--json] [--format table|json|yaml]

Set a validated setting override in the host settings file. A note is printed
to stderr when the key requires a daemon restart.
`
	settingsUnsetUsage = `usage: rsbx settings unset KEY

Remove a setting override and restore the built-in default.
`
	settingDockerVolume   = "sandbox.disk.dockerVolume"
	settingMCPRemoteHosts = "mcp.remote.allowedHosts"
)

// settingOutput mirrors the sbx settings record. Field order matches sbx's
// alphabetically ordered JSON, and value/default are typed rather than strings.
type settingOutput struct {
	Default         any    `json:"default" yaml:"default"`
	Description     string `json:"description" yaml:"description"`
	EnvVar          string `json:"env_var,omitempty" yaml:"env_var,omitempty"`
	Key             string `json:"key" yaml:"key"`
	RequiresRestart bool   `json:"requires_restart,omitempty" yaml:"requires_restart,omitempty"`
	Source          string `json:"source" yaml:"source"`
	Type            string `json:"type" yaml:"type"`
	Value           any    `json:"value" yaml:"value"`
}

func (r *Runner) settings(args []string) int {
	args, code, done := r.prepareFamilyArgs(settingsCommand, args)
	if done {
		return code
	}
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, settingsUsage)
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		return r.showCommandHelp(settingsHelp())
	case "ls":
		return r.settingsList(args[1:])
	case commandGet:
		return r.settingsGet(args[1:])
	case commandSet:
		return r.settingsSet(args[1:])
	case commandUnset:
		return r.settingsUnset(args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "rsbx settings: unknown subcommand %q\n", args[0])
		_, _ = fmt.Fprint(r.Err, settingsUsage)
		return 2
	}
}

func (r *Runner) settingsPath() string {
	if path := strings.TrimSpace(os.Getenv("GYREL_SETTINGS_FILE")); path != "" {
		return path
	}
	return settings.DefaultPath()
}

func (r *Runner) settingsList(args []string) int {
	args = reorderFlagArgs(args, map[string]bool{formatFlag: true})
	fs := r.newFlagSet("settings ls")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(settingsListHelp()) }
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("settings ls", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprint(r.Err, settingsListUsage)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	values, err := settings.Load(r.settingsPath())
	if err != nil {
		r.error(err)
		return 1
	}
	rows := settingRows(values)
	switch selected {
	case listFormatTable:
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "KEY\tVALUE\tTYPE\tSOURCE\tRESTART\tDESCRIPTION")
		for _, row := range rows {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", row.Key, formatSettingValue(row.Value), row.Type, row.Source, boolMarker(row.RequiresRestart), row.Description)
		}
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(rows)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(rows); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}

func boolMarker(value bool) string {
	if value {
		return "yes"
	}
	return ""
}

// settingRows lists the full catalog: the pinned Docker matrix plus Gyrel
// extensions, each with its override (file) or built-in default evaluated.
func settingRows(values settings.Values) []settingOutput {
	rows := make([]settingOutput, 0, 54)
	for _, entry := range settings.Catalog() {
		value, overridden := settingValue(values, entry)
		rows = append(rows, settingRow(entry, value, overridden))
	}
	return rows
}

func settingValue(values settings.Values, entry settings.Entry) (string, bool) {
	switch entry.Key {
	case "dns.upstream":
		return values.DNSUpstream, values.DNSUpstream != ""
	case "policy.profile":
		return values.DefaultPolicyProfile, values.DefaultPolicyProfile != ""
	case "defaults.cpus":
		return uintString(values.DefaultCPUs), values.DefaultCPUs != 0
	case "defaults.memory_mib":
		return uintString(values.DefaultMemoryMiB), values.DefaultMemoryMiB != 0
	case settingDockerVolume:
		return values.DockerVolumeSize, values.DockerVolumeSize != ""
	case settingMCPRemoteHosts:
		return values.MCPRemoteAllowedHosts, values.MCPRemoteAllowedHosts != ""
	}
	value, ok := values.Extra[entry.Key]
	return value, ok
}

func settingRow(entry settings.Entry, value string, overridden bool) settingOutput {
	source := "default"
	if overridden {
		source = "override"
	} else {
		value = entry.Default
	}
	return settingOutput{
		Default:         settingTypedValue(entry.Type, entry.Default),
		Description:     entry.Description,
		EnvVar:          entry.EnvVar,
		Key:             entry.Key,
		RequiresRestart: entry.Restart,
		Source:          source,
		Type:            entry.Type,
		Value:           settingTypedValue(entry.Type, value),
	}
}

// settingTypedValue converts the catalog's textual representation into the
// type sbx uses on the wire. String settings stay strings; json settings become
// objects, arrays, or scalars; empty integer defaults become 0.
func settingTypedValue(kind, text string) any {
	switch kind {
	case "bool":
		parsed, err := strconv.ParseBool(text)
		if err != nil {
			return false
		}
		return parsed
	case "int":
		parsed, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return int64(0)
		}
		return parsed
	case listFormatJSON:
		if text == "" {
			return nil
		}
		var parsed any
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			return text
		}
		return parsed
	default:
		return text
	}
}

// formatSettingValue renders a typed value for the human table and for
// settings get without --json.
func formatSettingValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case uint32:
		return strconv.FormatUint(uint64(typed), 10)
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprint(typed)
		}
		return string(data)
	}
}

func uintString(value uint32) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(value), 10)
}

func (r *Runner) settingsGet(args []string) int {
	args = reorderFlagArgs(args, map[string]bool{formatFlag: true})
	fs := r.newFlagSet("settings get")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(settingsGetHelp()) }
	jsonOutput := fs.Bool("json", false, "print the full setting record")
	format := fs.String("format", "", "output format: table, json or yaml")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("settings get", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx settings get KEY [--json]")
		return 2
	}
	values, err := settings.Load(r.settingsPath())
	if err != nil {
		r.error(err)
		return 1
	}
	row, found := findSettingRow(settingRows(values), fs.Arg(0))
	if !found {
		r.error(fmt.Errorf("unknown setting %q", fs.Arg(0)))
		return 2
	}
	if *jsonOutput {
		return r.printSettingRecord(row, listFormatJSON)
	}
	if *format == "" {
		_, _ = fmt.Fprintln(r.Out, formatSettingValue(row.Value))
		return 0
	}
	selected, err := resolveOperationFormat(*format, false)
	if err != nil {
		r.error(err)
		return 2
	}
	return r.printSettingRecord(row, selected)
}

func (r *Runner) printSettingRecord(row settingOutput, selected string) int {
	if selected == listFormatYAML {
		data, err := yaml.Marshal(row)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	}
	encoder := json.NewEncoder(r.Out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(row); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) settingsSet(args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		return r.showCommandHelp(settingsSetHelp())
	}
	args = reorderFlagArgs(args, map[string]bool{formatFlag: true})
	fs := r.newFlagSet("settings set")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(settingsSetHelp()) }
	jsonOutput := fs.Bool("json", false, "print the setting record as JSON")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("settings set", err)
	}
	if fs.NArg() != 2 {
		_, _ = fmt.Fprint(r.Err, settingsSetUsage)
		return 2
	}
	key, value := fs.Arg(0), fs.Arg(1)
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	values, err := settings.Load(r.settingsPath())
	if err != nil {
		r.error(err)
		return 1
	}
	if err := applySetting(&values, key, value); err != nil {
		r.error(err)
		return 2
	}
	if err := settings.Save(r.settingsPath(), values); err != nil {
		r.error(err)
		return 1
	}
	row, found := findSettingRow(settingRows(values), key)
	if !found {
		r.error(fmt.Errorf("unknown setting %q", key))
		return 2
	}
	restart := settingRestart(key)
	if selected == listFormatTable {
		_, _ = fmt.Fprintf(r.Out, "set %s\n", key)
		if restart {
			_, _ = fmt.Fprintf(r.Out, "restart gyreld to apply %s\n", key)
		}
	} else if code := r.printSettingRecord(row, selected); code != 0 {
		return code
	}
	if restart {
		_, _ = fmt.Fprintf(r.Err, "note: %s takes effect after the daemon restarts\n", key)
	}
	return 0
}

func (r *Runner) settingsUnset(args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		return r.showCommandHelp(settingsUnsetHelp())
	}
	if len(args) != 1 {
		_, _ = fmt.Fprint(r.Err, settingsUnsetUsage)
		return 2
	}
	values, err := settings.Load(r.settingsPath())
	if err != nil {
		r.error(err)
		return 1
	}
	if err := applySetting(&values, args[0], ""); err != nil {
		r.error(err)
		return 2
	}
	if err := settings.Save(r.settingsPath(), values); err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "unset %s\n", args[0])
	return 0
}

func settingRestart(key string) bool {
	entry, found := settings.Find(key)
	return found && entry.Restart
}

func findSettingRow(rows []settingOutput, key string) (settingOutput, bool) {
	for _, row := range rows {
		if row.Key == key {
			return row, true
		}
	}
	return settingOutput{}, false
}

func applySetting(values *settings.Values, key, value string) error {
	if handled, err := applyTypedSetting(values, key, value); handled {
		return err
	}
	entry, found := settings.Find(key)
	if !found {
		return fmt.Errorf("unknown setting %q", key)
	}
	if err := settings.ValidateValue(entry, value); err != nil {
		return err
	}
	if values.Extra == nil {
		values.Extra = map[string]string{}
	}
	if value == "" {
		delete(values.Extra, key)
	} else {
		values.Extra[key] = value
	}
	return nil
}

func applyTypedSetting(values *settings.Values, key, value string) (bool, error) {
	switch key {
	case "dns.upstream":
		value = strings.TrimSpace(value)
		if err := validateDNSUpstream(value); err != nil {
			return true, err
		}
		values.DNSUpstream = value
	case "policy.profile":
		switch value {
		case "", "allow-all", "deny-all", "balanced", "sbx-compat":
			values.DefaultPolicyProfile = value
		default:
			return true, errors.New("policy.profile must be allow-all, deny-all, balanced or sbx-compat")
		}
	case "defaults.cpus":
		parsed, err := parseSettingUint(value, 0, 64)
		if err != nil {
			return true, fmt.Errorf("defaults.cpus: %w", err)
		}
		values.DefaultCPUs = uint32(parsed) //nolint:gosec // parseSettingUint bounds the value to 64.
	case "defaults.memory_mib":
		parsed, err := parseSettingUint(value, 0, 32768)
		if err != nil {
			return true, fmt.Errorf("defaults.memory_mib: %w", err)
		}
		values.DefaultMemoryMiB = uint32(parsed) //nolint:gosec // parseSettingUint bounds the value to 32768.
	case settingDockerVolume, settingMCPRemoteHosts:
		return applyStringSetting(values, key, value)
	default:
		return false, nil
	}
	return true, nil
}

func applyStringSetting(values *settings.Values, key, value string) (bool, error) {
	switch key {
	case settingDockerVolume:
		if value != "" && !validVolumeSize(value) {
			return true, errors.New("sandbox.disk.dockerVolume must be a size such as 10g or 512m (minimum 512 MiB)")
		}
		values.DockerVolumeSize = value
	case settingMCPRemoteHosts:
		if err := validateMCPRemoteHostList(value); err != nil {
			return true, err
		}
		values.MCPRemoteAllowedHosts = value
	}
	return true, nil
}

func validateMCPRemoteHostList(value string) error {
	if value == "" {
		return nil
	}
	seen := make(map[string]struct{})
	for _, item := range strings.Split(value, ",") {
		host := strings.ToLower(strings.TrimSpace(item))
		if host == "" || strings.Contains(host, "*") || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil || !validDNSHost(host) {
			return errors.New("mcp.remote.allowedHosts must be comma-separated exact DNS hostnames (no wildcards or IP literals)")
		}
		if _, exists := seen[host]; exists {
			return errors.New("mcp.remote.allowedHosts contains a duplicate hostname")
		}
		seen[host] = struct{}{}
	}
	return nil
}

func parseSettingUint(value string, minValue, maxValue uint64) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed < minValue || parsed > maxValue {
		return 0, fmt.Errorf("must be an integer between %d and %d", minValue, maxValue)
	}
	return parsed, nil
}

func validateDNSUpstream(value string) error {
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") {
		return errors.New("DNS-over-HTTPS is not implemented; use a UDP HOST:PORT resolver")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("dns.upstream must be HOST:PORT")
	}
	if host == "" || net.ParseIP(host) == nil && !validDNSHost(host) {
		return errors.New("dns.upstream has an invalid host")
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsed == 0 {
		return errors.New("dns.upstream port must be 1..65535")
	}
	return nil
}

func validDNSHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validVolumeSize(value string) bool {
	if len(value) < 2 {
		return false
	}
	unit := value[len(value)-1]
	if unit != 'm' && unit != 'g' {
		return false
	}
	number, err := strconv.ParseUint(value[:len(value)-1], 10, 32)
	if err != nil {
		return false
	}
	bytes := number
	if unit == 'g' {
		bytes *= 1024
	}
	return bytes >= 512
}
