package command

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gyrel/sandboxes-core/ids"
	sdk "github.com/gyrel/sandboxes-go-sdk"
	"github.com/gyrel/slogx/redact"

	"github.com/gyrel/sandboxes-cli/internal/settings"
	"github.com/gyrel/sandboxes-cli/internal/version"
)

// The diagnose bundle builder collects host and daemon state, redacts it,
// scans the finished archive with slogx/redact.BundleGuard and publishes it
// only when the scan is clean. Every collector writes only disclosure fields;
// secret values, workspace host paths and rule targets never enter the bundle.
//
// D2: no DiagnoseBuild debug event is emitted here. The CLI structured logger
// is opt-in (-D/--debug) with an event allowlist and there is no always-on
// structured sink; the manifest.json records the build instead.
//
// D11: the bundle operation id is the canonical core/ids ULID operation
// identifier (github.com/gyrel/sandboxes-core/ids); it is correlation-only
// and never identity or authorization material.

const (
	diagnoseBundleSchemaVersion   = 1
	diagnoseBundleContractVersion = 1
	diagnoseBundlePrefix          = "gyrel-diagnose-"
	diagnoseBundleSuffix          = ".tar.gz"
	diagnoseBundleTimeLayout      = "20060102T150405Z"

	// D1: the daemon has no journal surface, so the journal summary file is
	// omitted entirely and only this limit string records the absence.
	diagnoseJournalLimitText = "journal_summary: no daemon surface in v1"
	// D4: the v1 approvals API exposes no option ids/labels.
	diagnoseApprovalOptionsLimit = "approvals: option ids and labels are not exposed by the v1 approvals API"
	// D3: GetSandboxPolicy does not exist in the vendored SDK; the sandbox
	// detail from List is used and per-host rule targets are omitted.
	diagnosePolicyRulesLimit      = "policies: sandbox network rule hosts and paths are omitted in v1 (counts only)"
	diagnoseSandboxWorkspacesLmt  = "sandboxes: workspace host paths and published ports are omitted"
	diagnoseTailRecordsLimit      = "logs: daemon tail capped at 2000 records"
	diagnoseTailBytesLimit        = "logs: daemon tail capped at 4 MiB"
	diagnoseLogMissingLimit       = "logs: daemon log not found in the state directory"
	diagnoseRedactedValue         = "[redacted]"
	diagnoseUnreachableLimit      = "daemon unreachable; daemon-side collectors were skipped"
	diagnoseBundlePublishPermMode = 0o600
)

const (
	bundleMemberManifest  = "manifest.json"
	bundleMemberVersions  = "versions.json"
	bundleMemberPlatform  = "platform.json"
	bundleMemberConfig    = "config.redacted.json"
	bundleMemberSandboxes = "sandboxes.redacted.json"
	bundleMemberPolicies  = "policies.redacted.json"
	bundleMemberApprovals = "approvals.pending.redacted.json"
	bundleMemberTail      = "logs/daemon.tail.jsonl"
	bundleMemberErrors    = "errors.json"
	bundleMemberReadme    = "README.txt"
)

var (
	// diagnoseBundleMaxBytes is the published-archive size cap (D8). It is a
	// variable so tests can exercise the trim and drop order cheaply.
	diagnoseBundleMaxBytes int64 = 8 << 20
	// D7: keys naming secret material are redacted wholesale.
	diagnoseSecretKeyPattern = regexp.MustCompile(`(?i)(secret|token|key|credential)`)
	// Home-shaped absolute paths collapse to "~" in every emitted string so
	// the archive stays free of the guard's own_home/foreign_home patterns.
	diagnoseHomeUnixPattern    = regexp.MustCompile(`(^|[\s"'=:(,])/(?:Users|home)/[^/"'\s\\]+`)
	diagnoseHomeWindowsPattern = regexp.MustCompile(`(?i)(^|[\s"'=:(,])[A-Za-z]:\\Users\\[^\\/:*?"'<>|\s]+`)
	// Optional members are dropped in this order when the size cap binds.
	diagnoseBundleDropOrder = []string{bundleMemberApprovals, bundleMemberPolicies, bundleMemberConfig}
)

// diagnoseBundleOptions carries the composed --bundle flag inputs.
type diagnoseBundleOptions struct {
	outPath  string
	sandbox  string
	since    time.Time
	paranoid bool
}

type diagnoseBundleMember struct {
	path string
	data []byte
}

// --- file schemas -----------------------------------------------------------

type diagnoseCLIBuild struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

type diagnoseDaemonVersion struct {
	Version    string `json:"version,omitempty"`
	APIVersion string `json:"api_version,omitempty"`
	// ErrorClass is the only datum kept when the daemon could not answer; the
	// error message itself is never written (D5).
	ErrorClass string `json:"error_class,omitempty"`
}

type diagnoseVersionsFile struct {
	SchemaVersion int                    `json:"schema_version"`
	CLI           diagnoseCLIBuild       `json:"cli"`
	Daemon        *diagnoseDaemonVersion `json:"daemon,omitempty"`
}

type diagnoseVirtualizationOut struct {
	Supported bool   `json:"supported"`
	Probe     string `json:"probe"`
}

type diagnoseToolOut struct {
	Name  string `json:"name"`
	Path  string `json:"path,omitempty"`
	Found bool   `json:"found"`
}

type diagnosePlatformFile struct {
	SchemaVersion  int                       `json:"schema_version"`
	GOOS           string                    `json:"goos"`
	GOARCH         string                    `json:"goarch"`
	Virtualization diagnoseVirtualizationOut `json:"virtualization"`
	Tools          []diagnoseToolOut         `json:"tools"`
}

type diagnoseConfigEntry struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Redacted bool   `json:"redacted,omitempty"`
}

type diagnoseConfigFile struct {
	SchemaVersion int                   `json:"schema_version"`
	Settings      []diagnoseConfigEntry `json:"settings"`
}

type diagnoseSandboxOut struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	State         string `json:"state"`
	Agent         string `json:"agent,omitempty"`
	Image         string `json:"image,omitempty"`
	PolicyProfile string `json:"policy_profile,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
}

type diagnoseSandboxesFile struct {
	SchemaVersion int                  `json:"schema_version"`
	Sandboxes     []diagnoseSandboxOut `json:"sandboxes"`
}

type diagnoseSandboxPolicyOut struct {
	Sandbox    string `json:"sandbox"`
	Profile    string `json:"policy_profile,omitempty"`
	AllowRules int    `json:"allow_rule_count"`
	DenyRules  int    `json:"deny_rule_count"`
}

type diagnosePoliciesFile struct {
	SchemaVersion int                        `json:"schema_version"`
	GlobalProfile string                     `json:"global_profile,omitempty"`
	GlobalAllow   int                        `json:"global_allow_count"`
	GlobalDeny    int                        `json:"global_deny_count"`
	Sandboxes     []diagnoseSandboxPolicyOut `json:"sandboxes"`
}

type diagnoseApprovalOut struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	State           string   `json:"state"`
	SandboxID       string   `json:"sandbox_id,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
	Headers         []string `json:"header_names,omitempty"`
	EnvNames        []string `json:"env_names,omitempty"`
	DestinationHost string   `json:"destination_host,omitempty"`
	DestinationPath string   `json:"destination_path,omitempty"`
}

type diagnoseApprovalsFile struct {
	SchemaVersion int                   `json:"schema_version"`
	Approvals     []diagnoseApprovalOut `json:"approvals"`
}

type diagnoseBundleError struct {
	Member string `json:"member"`
	Class  string `json:"error_class"`
}

type diagnoseBundleErrorFile struct {
	SchemaVersion int                   `json:"schema_version"`
	Errors        []diagnoseBundleError `json:"errors"`
}

type diagnoseManifestPlatform struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	// Probe holds the existing host platform probe result. The CLI has no
	// uname syscall probe, so the documented D11 "uname line" is served by
	// this string; the deviation is recorded in EXECUTOR-REPORT.md.
	Probe string `json:"platform_probe"`
}

type diagnoseManifestFile struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type diagnoseManifest struct {
	SchemaVersion     int                      `json:"schema_version"`
	BundleOpID        string                   `json:"bundle_op_id"`
	GeneratedAt       string                   `json:"generated_at"`
	Platform          diagnoseManifestPlatform `json:"platform"`
	Files             []diagnoseManifestFile   `json:"files"`
	Limits            []string                 `json:"limits"`
	RedactionContract int                      `json:"redaction_contract_version"`
}

// --- collection state -------------------------------------------------------

type diagnoseBundleBuild struct {
	paranoid     bool
	home         string
	opID         string
	generatedAt  string
	staticLimits []string

	versions   *diagnoseVersionsFile
	platform   *diagnosePlatformFile
	config     *diagnoseConfigFile
	sandboxes  *diagnoseSandboxesFile
	policies   *diagnosePoliciesFile
	approvals  *diagnoseApprovalsFile
	tailLines  [][]byte
	trimmed    int
	omitted    []string
	collectErr []diagnoseBundleError
}

func newDiagnoseBundleBuild(paranoid bool) *diagnoseBundleBuild {
	home, _ := os.UserHomeDir()
	return &diagnoseBundleBuild{
		paranoid:    paranoid,
		home:        home,
		opID:        diagnoseNewBundleOpID(),
		generatedAt: time.Now().UTC().Format(time.RFC3339),
		versions:    &diagnoseVersionsFile{SchemaVersion: diagnoseBundleSchemaVersion, CLI: diagnoseCLIBuild{Version: version.Version, Commit: version.Commit}},
		sandboxes:   &diagnoseSandboxesFile{SchemaVersion: diagnoseBundleSchemaVersion, Sandboxes: []diagnoseSandboxOut{}},
		policies:    &diagnosePoliciesFile{SchemaVersion: diagnoseBundleSchemaVersion, Sandboxes: []diagnoseSandboxPolicyOut{}},
		approvals:   &diagnoseApprovalsFile{SchemaVersion: diagnoseBundleSchemaVersion, Approvals: []diagnoseApprovalOut{}},
	}
}

func (b *diagnoseBundleBuild) record(member string, err error) {
	b.collectErr = append(b.collectErr, diagnoseBundleError{Member: member, Class: diagnoseErrorClass(err)})
}

// normalizeHome collapses home-shaped absolute paths to "~". It keys off the
// same path shapes the redaction guard reports (own_home/foreign_home), so it
// does not depend on the current user's home directory.
func (b *diagnoseBundleBuild) normalizeHome(value string) string {
	if value == "" {
		return value
	}
	value = diagnoseHomeUnixPattern.ReplaceAllString(value, "$1~")
	value = diagnoseHomeWindowsPattern.ReplaceAllString(value, "$1~")
	if b.home != "" {
		value = strings.ReplaceAll(value, b.home, "~")
	}
	return value
}

func (b *diagnoseBundleBuild) nameOrHash(name string) string {
	if !b.paranoid || name == "" {
		return name
	}
	return diagnoseHashName(name)
}

// --- collectors -------------------------------------------------------------

func (b *diagnoseBundleBuild) addDaemonUnavailable(err error) {
	class := diagnoseErrorClass(err)
	b.versions.Daemon = &diagnoseDaemonVersion{ErrorClass: class}
	b.limitsAppend("versions: daemon version unavailable: " + class)
	b.limitsAppend(diagnoseUnreachableLimit)
	b.record(bundleMemberVersions, err)
	b.limitsAppend("sandboxes: no daemon surface (unreachable)")
	b.limitsAppend("policies: no daemon surface (unreachable)")
	b.limitsAppend("approvals: no daemon surface (unreachable)")
}

func (b *diagnoseBundleBuild) limitsAppend(limit string) {
	for _, existing := range b.limitStrings() {
		if existing == limit {
			return
		}
	}
	b.staticLimits = append(b.staticLimits, limit)
}

func (b *diagnoseBundleBuild) addVersions(ctx context.Context, client sdk.Client) {
	info, err := sdk.Version(client).Get(ctx)
	if err != nil {
		b.versions.Daemon = &diagnoseDaemonVersion{ErrorClass: diagnoseErrorClass(err)}
		b.limitsAppend("versions: daemon version unavailable: " + diagnoseErrorClass(err))
		b.record(bundleMemberVersions, err)
		return
	}
	b.versions.Daemon = &diagnoseDaemonVersion{Version: info.Version, APIVersion: info.APIVersion}
}

func (b *diagnoseBundleBuild) addPlatform() {
	supported, detail := hostVirtualizationSupport()
	b.platform = &diagnosePlatformFile{
		SchemaVersion:  diagnoseBundleSchemaVersion,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		Virtualization: diagnoseVirtualizationOut{Supported: supported, Probe: b.normalizeHome(detail)},
		Tools:          b.diagnoseToolChecks(),
	}
}

func (b *diagnoseBundleBuild) diagnoseToolChecks() []diagnoseToolOut {
	tools := make([]diagnoseToolOut, 0, 2)
	for _, name := range []string{"mkfs.erofs", "mkfs.ext4"} {
		entry := diagnoseToolOut{Name: name}
		if path, err := lookPath(name); err == nil && path != "" {
			entry.Found = true
			// Tool paths may embed the user's home; the archive guard treats
			// unnormalized homes as a refusal, so normalize before writing.
			entry.Path = b.normalizeHome(path)
		}
		tools = append(tools, entry)
	}
	return tools
}

func (b *diagnoseBundleBuild) addConfig(path string) {
	b.config = &diagnoseConfigFile{SchemaVersion: diagnoseBundleSchemaVersion, Settings: []diagnoseConfigEntry{}}
	values, err := settings.Load(path)
	if err != nil {
		b.limitsAppend("config: settings unavailable: " + diagnoseErrorClass(err))
		b.record(bundleMemberConfig, err)
		return
	}
	b.config.Settings = diagnoseConfigEntries(b, values)
}

func diagnoseConfigEntries(b *diagnoseBundleBuild, values settings.Values) []diagnoseConfigEntry {
	entries := make([]diagnoseConfigEntry, 0, 8+len(values.Extra))
	add := func(key, value string) {
		if value == "" {
			return
		}
		if diagnoseSecretKeyPattern.MatchString(key) {
			entries = append(entries, diagnoseConfigEntry{Key: key, Value: diagnoseRedactedValue, Redacted: true})
			return
		}
		entries = append(entries, diagnoseConfigEntry{Key: key, Value: b.normalizeHome(value)})
	}
	add("dns_upstream", values.DNSUpstream)
	add("default_policy_profile", values.DefaultPolicyProfile)
	if values.DefaultCPUs != 0 {
		entries = append(entries, diagnoseConfigEntry{Key: "default_cpus", Value: strconv.FormatUint(uint64(values.DefaultCPUs), 10)})
	}
	if values.DefaultMemoryMiB != 0 {
		entries = append(entries, diagnoseConfigEntry{Key: "default_memory_mib", Value: strconv.FormatUint(uint64(values.DefaultMemoryMiB), 10)})
	}
	add("docker_volume_size", values.DockerVolumeSize)
	add("mcp_remote_allowed_hosts", values.MCPRemoteAllowedHosts)
	extra := make([]string, 0, len(values.Extra))
	for key := range values.Extra {
		extra = append(extra, key)
	}
	sort.Strings(extra)
	for _, key := range extra {
		add(key, values.Extra[key])
	}
	return entries
}

func (b *diagnoseBundleBuild) addSandboxes(ctx context.Context, client sdk.Client, sandbox string) []sdk.Sandbox {
	items, err := diagnoseListSandboxes(ctx, client, sandbox)
	if err != nil {
		b.limitsAppend("sandboxes: daemon list unavailable: " + diagnoseErrorClass(err))
		b.record(bundleMemberSandboxes, err)
		return nil
	}
	b.limitsAppend(diagnoseSandboxWorkspacesLmt)
	out := make([]diagnoseSandboxOut, 0, len(items))
	for i := range items {
		out = append(out, b.sandboxOut(&items[i]))
	}
	b.sandboxes.Sandboxes = out
	return items
}

func (b *diagnoseBundleBuild) sandboxOut(item *sdk.Sandbox) diagnoseSandboxOut {
	out := diagnoseSandboxOut{
		ID:            item.ID,
		Name:          b.nameOrHash(item.Name),
		State:         item.State,
		Agent:         item.Agent,
		Image:         b.nameOrHash(item.Image),
		PolicyProfile: item.PolicyProfile,
	}
	if !item.CreatedAt.IsZero() {
		out.CreatedAt = item.CreatedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func diagnoseListSandboxes(ctx context.Context, client sdk.Client, sandbox string) ([]sdk.Sandbox, error) {
	items := make([]sdk.Sandbox, 0, 16)
	token := ""
	seen := map[string]struct{}{}
	for {
		page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: 100, PageToken: token})
		if err != nil {
			return nil, err
		}
		for i := range page.Items {
			if sandbox == "" || page.Items[i].Name == sandbox || page.Items[i].ID == sandbox {
				items = append(items, page.Items[i])
			}
		}
		if page.NextPageToken == "" {
			return items, nil
		}
		if _, ok := seen[page.NextPageToken]; ok {
			return items, nil
		}
		seen[page.NextPageToken] = struct{}{}
		token = page.NextPageToken
	}
}

func (b *diagnoseBundleBuild) addPolicies(ctx context.Context, client sdk.Client, sandboxes []sdk.Sandbox) {
	b.limitsAppend(diagnosePolicyRulesLimit)
	policies := sdk.Policies(client)
	if profile, err := policies.GetPolicyProfile(ctx); err == nil {
		b.policies.GlobalProfile = profile
	} else {
		b.limitsAppend("policies: global profile unavailable: " + diagnoseErrorClass(err))
		b.record(bundleMemberPolicies, err)
	}
	allow, deny, err := globalPolicyForList(ctx, client)
	if err != nil {
		b.limitsAppend("policies: global rules unavailable: " + diagnoseErrorClass(err))
		b.record(bundleMemberPolicies, err)
	} else {
		b.policies.GlobalAllow = len(allow)
		b.policies.GlobalDeny = len(deny)
	}
	entries := make([]diagnoseSandboxPolicyOut, 0, len(sandboxes))
	for i := range sandboxes {
		entries = append(entries, diagnoseSandboxPolicyOut{
			Sandbox:    b.nameOrHash(sandboxes[i].Name),
			Profile:    sandboxes[i].PolicyProfile,
			AllowRules: len(sandboxes[i].Allow),
			DenyRules:  len(sandboxes[i].Deny),
		})
	}
	b.policies.Sandboxes = entries
}

func (b *diagnoseBundleBuild) addApprovals(ctx context.Context, client sdk.Client, sandbox string) {
	b.limitsAppend(diagnoseApprovalOptionsLimit)
	items, err := sdk.Approvals(client).ListApprovals(ctx, sandbox)
	if err != nil {
		b.limitsAppend("approvals: pending list unavailable: " + diagnoseErrorClass(err))
		b.record(bundleMemberApprovals, err)
		return
	}
	entries := make([]diagnoseApprovalOut, 0, len(items))
	for i := range items {
		entries = append(entries, b.approvalOut(items[i]))
	}
	b.approvals.Approvals = entries
}

func (b *diagnoseBundleBuild) approvalOut(item sdk.Approval) diagnoseApprovalOut {
	out := diagnoseApprovalOut{
		ID:              item.ID,
		Kind:            string(item.Kind),
		State:           string(item.State),
		SandboxID:       item.SandboxID,
		DestinationHost: item.DestinationHost,
		DestinationPath: b.normalizeHome(item.DestinationPath),
	}
	if !item.CreatedAt.IsZero() {
		out.CreatedAt = item.CreatedAt.UTC().Format(time.RFC3339)
	}
	for _, header := range item.Headers {
		out.Headers = append(out.Headers, header.Name)
	}
	out.EnvNames = append(out.EnvNames, item.EnvNames...)
	return out
}

func (r *Runner) addDaemonTail(b *diagnoseBundleBuild, since time.Time) {
	path := filepath.Join(diagnoseStateDir(r.Socket), "daemon.log")
	file, err := os.Open(path) // #nosec G304 -- fixed daemon state path, read-only collector
	if err != nil {
		b.tailLines = nil
		if errors.Is(err, os.ErrNotExist) {
			b.limitsAppend(diagnoseLogMissingLimit)
		} else {
			b.limitsAppend("logs: daemon log unreadable: " + diagnoseErrorClass(err))
			b.record(bundleMemberTail, err)
		}
		return
	}
	defer func() { _ = file.Close() }()
	data, err := diagnoseLogTail(file, since)
	if err != nil {
		b.limitsAppend("logs: daemon tail read failed: " + diagnoseErrorClass(err))
		b.record(bundleMemberTail, err)
		return
	}
	b.tailLines = diagnoseSplitLines(data)
	if len(b.tailLines) >= diagnoseTailLines {
		b.limitsAppend(diagnoseTailRecordsLimit)
	}
	if len(data) >= diagnoseTailBytes {
		b.limitsAppend(diagnoseTailBytesLimit)
	}
}

func diagnoseSplitLines(data []byte) [][]byte {
	data = bytes.TrimRight(data, "\n")
	if len(data) == 0 {
		return [][]byte{}
	}
	return bytes.Split(data, []byte("\n"))
}

// --- members, manifest, archive ---------------------------------------------

func (b *diagnoseBundleBuild) tailData() []byte {
	var out bytes.Buffer
	// The daemon tail is embedded verbatim: daemon-side redaction (P0.1) is
	// the normalization boundary, and the archive guard treats any raw home
	// path or secret as a refusal — diagnose doubles as a leak tripwire.
	for _, line := range b.tailLines {
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func (b *diagnoseBundleBuild) members() []diagnoseBundleMember {
	members := make([]diagnoseBundleMember, 0, 10)
	add := func(path string, value any) {
		data, err := diagnoseJSONBytes(value)
		if err != nil {
			b.softFail(path, err)
			return
		}
		members = append(members, diagnoseBundleMember{path: path, data: data})
	}
	if b.versions != nil {
		add(bundleMemberVersions, b.versions)
	}
	if b.platform != nil {
		add(bundleMemberPlatform, b.platform)
	}
	if b.config != nil {
		add(bundleMemberConfig, b.config)
	}
	if b.sandboxes != nil {
		add(bundleMemberSandboxes, b.sandboxes)
	}
	if b.policies != nil {
		add(bundleMemberPolicies, b.policies)
	}
	if b.approvals != nil {
		add(bundleMemberApprovals, b.approvals)
	}
	members = append(members,
		diagnoseBundleMember{path: bundleMemberTail, data: b.tailData()},
		diagnoseBundleMember{path: bundleMemberErrors, data: b.errorsData()},
		diagnoseBundleMember{path: bundleMemberReadme, data: []byte(diagnoseBundleReadme)},
	)
	return members
}

func (b *diagnoseBundleBuild) errorsData() []byte {
	file := diagnoseBundleErrorFile{SchemaVersion: diagnoseBundleSchemaVersion, Errors: b.collectErr}
	if file.Errors == nil {
		file.Errors = []diagnoseBundleError{}
	}
	data, err := diagnoseJSONBytes(file)
	if err != nil {
		return []byte("{}\n")
	}
	return data
}

func (b *diagnoseBundleBuild) softFail(member string, err error) {
	b.collectErr = append(b.collectErr, diagnoseBundleError{Member: member, Class: diagnoseErrorClass(err)})
}

func (b *diagnoseBundleBuild) limitStrings() []string {
	limits := make([]string, 0, len(b.staticLimits)+8)
	limits = append(limits, diagnoseJournalLimitText)
	limits = append(limits, b.staticLimits...)
	if b.trimmed > 0 {
		limits = append(limits, fmt.Sprintf("bundle cap: trimmed daemon tail to %d records", len(b.tailLines)))
	}
	for _, name := range b.omitted {
		limits = append(limits, "bundle cap: omitted "+name)
	}
	return limits
}

func (b *diagnoseBundleBuild) assemble() ([]byte, error) {
	members := b.members()
	manifest, err := b.manifestData(members)
	if err != nil {
		return nil, err
	}
	ordered := append([]diagnoseBundleMember{{path: bundleMemberManifest, data: manifest}}, members...)
	return diagnoseTarGz(ordered)
}

func (b *diagnoseBundleBuild) manifestData(members []diagnoseBundleMember) ([]byte, error) {
	files := make([]diagnoseManifestFile, 0, len(members))
	for _, member := range members {
		sum := sha256.Sum256(member.data)
		files = append(files, diagnoseManifestFile{
			Path:      member.path,
			SHA256:    hex.EncodeToString(sum[:]),
			SizeBytes: int64(len(member.data)),
		})
	}
	_, probe := hostVirtualizationSupport()
	manifest := diagnoseManifest{
		SchemaVersion:     diagnoseBundleSchemaVersion,
		BundleOpID:        b.opID,
		GeneratedAt:       b.generatedAt,
		Platform:          diagnoseManifestPlatform{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Probe: b.normalizeHome(probe)},
		Files:             files,
		Limits:            b.limitStrings(),
		RedactionContract: diagnoseBundleContractVersion,
	}
	return diagnoseJSONBytes(manifest)
}

func (b *diagnoseBundleBuild) hasMember(name string) bool {
	switch name {
	case bundleMemberApprovals:
		return b.approvals != nil
	case bundleMemberPolicies:
		return b.policies != nil
	case bundleMemberConfig:
		return b.config != nil
	default:
		return false
	}
}

func (b *diagnoseBundleBuild) dropMember(name string) {
	switch name {
	case bundleMemberApprovals:
		b.approvals = nil
	case bundleMemberPolicies:
		b.policies = nil
	case bundleMemberConfig:
		b.config = nil
	}
}

// finalArchive enforces D8: trim oldest tail lines first, then drop optional
// members in approvals, policies, config order, then refuse.
func (b *diagnoseBundleBuild) finalArchive() ([]byte, error) {
	for {
		archive, err := b.assemble()
		if err != nil {
			return nil, err
		}
		if int64(len(archive)) <= diagnoseBundleMaxBytes {
			return archive, nil
		}
		if len(b.tailLines) > 0 {
			drop := len(b.tailLines) / 4
			if drop < 1 {
				drop = 1
			}
			b.tailLines = b.tailLines[drop:]
			b.trimmed += drop
			continue
		}
		dropped := false
		for _, name := range diagnoseBundleDropOrder {
			if b.hasMember(name) {
				b.dropMember(name)
				b.omitted = append(b.omitted, name)
				dropped = true
				break
			}
		}
		if !dropped {
			return nil, errors.New("diagnostic bundle exceeds the size cap after trimming the tail and dropping optional files")
		}
	}
}

func diagnoseJSONBytes(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func diagnoseTarGz(members []diagnoseBundleMember) ([]byte, error) {
	var raw bytes.Buffer
	gzipWriter := gzip.NewWriter(&raw)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, member := range members {
		header := &tar.Header{
			Name:    member.path,
			Mode:    diagnoseBundlePublishPermMode,
			Size:    int64(len(member.data)),
			ModTime: time.Unix(0, 0).UTC(),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := tarWriter.Write(member.data); err != nil {
			return nil, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return raw.Bytes(), nil
}

// --- helpers ----------------------------------------------------------------

func diagnoseHashName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:6])
}

func diagnoseErrorClass(err error) string {
	var sdkErr *sdk.Error
	if errors.As(err, &sdkErr) && sdkErr.Code != "" {
		return sdkErr.Code
	}
	return fmt.Sprintf("%T", err)
}

func diagnoseNewBundleOpID() string {
	return ids.NewOpID()
}

func parseDiagnoseSince(value string, now time.Time) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	if at, err := time.Parse(time.RFC3339, value); err == nil {
		return at.UTC(), nil
	}
	span, err := time.ParseDuration(value)
	if err != nil || span < 0 {
		return time.Time{}, errors.New(`--since must be an RFC 3339 time or a positive duration such as 30m`)
	}
	return now.Add(-span).UTC(), nil
}

// --- publication ------------------------------------------------------------

func (r *Runner) resolveDiagnoseBundleTarget(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("cannot resolve the working directory: %w", err)
		}
		name = filepath.Join(cwd, diagnoseBundlePrefix+time.Now().UTC().Format(diagnoseBundleTimeLayout)+diagnoseBundleSuffix)
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(abs)
	if info, err := os.Lstat(dir); err != nil {
		return "", fmt.Errorf("bundle output directory is unavailable: %w", err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("refusing to write the bundle under a symlinked directory")
	}
	if info, err := os.Lstat(abs); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("refusing to write the bundle onto a symlink target")
	}
	for _, protected := range r.diagnoseBundleProtectedDirs() {
		if diagnosePathWithin(abs, protected) {
			return "", errors.New("refusing to write the bundle inside the daemon state directory")
		}
	}
	return abs, nil
}

// diagnoseStateDirEnvWarned ensures the legacy-env deprecation note is emitted
// at most once per process, no matter how many collectors read the state dir.
var diagnoseStateDirEnvWarned sync.Once

// diagnoseStateDirEnv returns the daemon state directory override from the
// environment. GYREL_STATE_DIR is the primary name. The pre-rename
// RHEIC_STATE_DIR spelling is still honored as a legacy-compat fallback for
// existing deployments, and reading it prints a one-time deprecation note.
func (r *Runner) diagnoseStateDirEnv() string {
	if dir := strings.TrimSpace(os.Getenv("GYREL_STATE_DIR")); dir != "" {
		return dir
	}
	if dir := strings.TrimSpace(os.Getenv("RHEIC_STATE_DIR")); dir != "" { // legacy-compat: pre-rename env spelling, kept for data-migration safety
		diagnoseStateDirEnvWarned.Do(func() {
			_, _ = fmt.Fprintf(r.Err, "warning: RHEIC_STATE_DIR is deprecated; use GYREL_STATE_DIR\n")
		})
		return dir
	}
	return ""
}

func (r *Runner) diagnoseBundleProtectedDirs() []string {
	dirs := make([]string, 0, 2)
	if dir := r.diagnoseStateDirEnv(); dir != "" {
		dirs = append(dirs, dir)
	}
	if dir := diagnoseStateDir(r.Socket); dir != "" {
		dirs = append(dirs, dir)
	}
	for i := range dirs {
		if abs, err := filepath.Abs(dirs[i]); err == nil {
			dirs[i] = abs
		}
	}
	return dirs
}

func diagnosePathWithin(path, dir string) bool {
	if dir == "" {
		return false
	}
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}

// publishDiagnoseBundle writes the archive to a temp file in the target
// directory, runs the redaction guard over the finished archive and only then
// claims the final path with O_EXCL and renames into place (D10). Any guard hit
// deletes the temp file and returns a refusal; the final path is never touched.
func (r *Runner) publishDiagnoseBundle(target string, archive []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(target), diagnoseBundlePrefix+"*.tmp") // #nosec G304 -- directory is guarded above
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if _, err := temp.Write(archive); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := r.guardDiagnoseBundleArchive(tempName); err != nil {
		return err
	}
	sentinel, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, diagnoseBundlePublishPermMode) // #nosec G304 -- target is guarded above
	if err != nil {
		return fmt.Errorf("refusing to publish over an existing bundle target: %w", err)
	}
	_ = sentinel.Close()
	if err := os.Rename(tempName, target); err != nil {
		_ = os.Remove(target)
		return err
	}
	return nil
}

func (r *Runner) guardDiagnoseBundleArchive(path string) error {
	file, err := os.Open(path) // #nosec G304 -- temp archive created by this process
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	home, _ := os.UserHomeDir()
	violations, _, err := redact.BundleGuard(file, redact.Options{HomeUser: filepath.Base(home)})
	if err != nil {
		// Guard errors can quote archive-controlled names; keep them generic.
		return errors.New("diagnostic bundle could not be scanned; refusing to publish")
	}
	if len(violations) == 0 {
		return nil
	}
	for _, violation := range violations {
		name := violation.Path
		if !diagnoseSafeMember.MatchString(name) {
			name = "[unrecognized member]"
		}
		_, _ = fmt.Fprintf(r.Err, "%s %s line %d offset %d\n", violation.Rule, name, violation.Line, violation.Offset)
	}
	return fmt.Errorf("diagnostic bundle refused: %d redaction hits", len(violations))
}

// --- entry point ------------------------------------------------------------

func (r *Runner) buildDiagnoseBundle(ctx context.Context, opts diagnoseBundleOptions) (string, error) {
	target, err := r.resolveDiagnoseBundleTarget(opts.outPath)
	if err != nil {
		return "", err
	}
	build := newDiagnoseBundleBuild(opts.paranoid)
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, clientErr := r.client()
	if clientErr != nil {
		build.addDaemonUnavailable(clientErr)
	} else {
		defer func() { _ = client.Close() }()
		sandboxes := build.addSandboxes(checkCtx, client, opts.sandbox)
		build.addVersions(checkCtx, client)
		build.addPolicies(checkCtx, client, sandboxes)
		build.addApprovals(checkCtx, client, opts.sandbox)
	}
	build.addPlatform()
	build.addConfig(r.settingsPath())
	r.addDaemonTail(build, opts.since)
	archive, err := build.finalArchive()
	if err != nil {
		return "", err
	}
	if err := r.publishDiagnoseBundle(target, archive); err != nil {
		return "", err
	}
	return target, nil
}

const diagnoseBundleReadme = `GYREL diagnose bundle
=====================

This archive was produced by "rsbx diagnose --bundle". It is a redacted
snapshot for bug reports. manifest.json holds the machine-readable file
inventory with SHA-256 digests and sizes, the bundle operation id, the
platform identity and the list of limits that shaped this bundle.

Contents
  manifest.json                     inventory, operation id, limits
  versions.json                     CLI build and daemon version (class only when unreachable)
  platform.json                     host platform probe: OS, arch, virtualization, mkfs tools
  config.redacted.json              host settings; secret-bearing keys show [redacted]
  sandboxes.redacted.json           sandbox inventory without workspace host paths
  policies.redacted.json            policy profiles and rule counts, no rule targets
  approvals.pending.redacted.json   pending approval ids, kinds, states and boundary names
  logs/daemon.tail.jsonl            bounded daemon log tail (2000 records, 4 MiB)
  errors.json                       non-fatal collection error class names
  README.txt                        this file

Absences
  journal.summary.json is not included: there is no daemon journal surface
  in v1. Approval option ids and labels, per-host network rule targets,
  workspace host paths and every secret value are intentionally absent.

Redaction and refusal
  Before publishing, the finished archive is scanned by the redaction guard.
  Any suspected secret, high-entropy run, URL credential or home-directory
  path (including the daemon log tail) makes the builder delete the temporary
  archive and exit 1, printing "rule member line offset" per hit. No bundle
  file is created on refusal, so a rejected bundle cannot leak by accident.

Paranoid mode
  With --paranoid, every sandbox and image name is replaced by the first 12
  hex characters of its SHA-256 hash. The mapping is deterministic, so the
  same name yields the same token across bundles while the names themselves
  never leave the host.

Sharing
  Verify the archive first: rsbx diagnose --verify FILE. Then attach the
  .tar.gz file to a GitHub issue on the gyrel/sandboxes-cli repository. The
  scan is heuristic: a clean scan does not prove the bundle is safe to share.
`
