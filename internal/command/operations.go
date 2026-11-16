package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

type operationOutput struct {
	ID         string `json:"id" yaml:"id"`
	SandboxID  string `json:"sandbox_id" yaml:"sandbox_id"`
	Kind       string `json:"kind" yaml:"kind"`
	State      string `json:"state" yaml:"state"`
	Generation int64  `json:"generation" yaml:"generation"`
	Error      string `json:"error,omitempty" yaml:"error,omitempty"`
	CreatedAt  string `json:"created_at" yaml:"created_at"`
	UpdatedAt  string `json:"updated_at" yaml:"updated_at"`
}

// mutationOutput mirrors the sbx mutation result used by rm and stop:
// {action, resource, name}. ID and error stay available as optional fields,
// but successful sbx output leaves them out.
type mutationOutput struct {
	Action   string `json:"action" yaml:"action"`
	Resource string `json:"resource" yaml:"resource"`
	Name     string `json:"name" yaml:"name"`
	ID       string `json:"id,omitempty" yaml:"id,omitempty"`
	Error    string `json:"error,omitempty" yaml:"error,omitempty"`
}

// sandboxMutations builds the sbx action records for a successful batch.
func sandboxMutations(action string, names []string) []mutationOutput {
	items := make([]mutationOutput, 0, len(names))
	for _, name := range names {
		items = append(items, mutationOutput{Action: action, Resource: "sandbox", Name: name})
	}
	return items
}

func renderMutations(out io.Writer, format string, items []mutationOutput) error {
	if items == nil {
		items = []mutationOutput{}
	}
	switch format {
	case listFormatJSON:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(items)
	case listFormatYAML:
		data, err := yaml.Marshal(items)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		for i := range items {
			_, _ = fmt.Fprintf(out, "%s %s %s\n", items[i].Action, items[i].Resource, items[i].Name)
		}
		return nil
	}
}

func resolveOperationFormat(format string, jsonOutput bool) (string, error) {
	if jsonOutput {
		if format != listFormatTable {
			return "", errors.New("--json cannot be combined with an explicit --format")
		}
		return listFormatJSON, nil
	}
	switch format {
	case listFormatTable, listFormatJSON, listFormatYAML:
		return format, nil
	default:
		return "", fmt.Errorf("invalid format %q; use table, json or yaml", format)
	}
}

func renderOperations(out io.Writer, format string, operations []*sdk.Operation) error {
	items := make([]operationOutput, 0, len(operations))
	for _, op := range operations {
		if op == nil {
			continue
		}
		items = append(items, operationOutput{
			ID: op.ID, SandboxID: op.SandboxID, Kind: op.Kind, State: op.State,
			Generation: op.Generation, Error: op.Error,
			CreatedAt: operationTime(op.CreatedAt), UpdatedAt: operationTime(op.UpdatedAt),
		})
	}
	switch format {
	case listFormatJSON:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(items)
	case listFormatYAML:
		data, err := yaml.Marshal(items)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		for i := range items {
			_, _ = fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", items[i].ID, items[i].Kind, items[i].State, items[i].Error)
		}
		return nil
	}
}

func operationTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
