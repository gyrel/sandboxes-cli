package command

import (
	"encoding/json"
	"fmt"
	"io"

	sdk "github.com/rheic/sandboxes-go-sdk"
	"gopkg.in/yaml.v3"
)

// renderSandboxDetail renders one sandbox. Structured formats deliberately use
// the same schema as ls so "get --json" is a single-record view of the same
// resource; the table format keeps the detailed human-readable block.
func renderSandboxDetail(out io.Writer, format string, sb *sdk.Sandbox) error {
	if sb == nil {
		_, err := fmt.Fprintln(out, "not found")
		return err
	}
	switch format {
	case listFormatJSON:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(sandboxOutputFor(sb))
	case listFormatYAML:
		data, err := yaml.Marshal(sandboxOutputFor(sb))
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		_, err := fmt.Fprintf(out, "id: %s\nname: %s\nstate: %s\nagent: %s\npolicy_profile: %s\ndetached: %t\nlast_used_at: %s\nimage: %s\nworkspace: %s\nworkspaces: %s\nports: %s\nallow: %s\ndeny: %s\ncpus: %d\nmemory_mib: %d\nstopped_at: %s\ngeneration: %d\ncreated: %s\nupdated: %s\n",
			sb.ID, sb.Name, sb.State, formatAgent(sb.Agent), sb.PolicyProfile, sb.Detached, formatTime(sb.LastUsedAt), sb.Image, sb.Workspace, formatWorkspaces(sb), formatPorts(sb), formatRules(sb.Allow), formatRules(sb.Deny),
			sb.CPUs, sb.MemoryMiB, formatTime(sb.StoppedAt), sb.Generation, formatTime(sb.CreatedAt), formatTime(sb.UpdatedAt))
		return err
	}
}
