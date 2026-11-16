package command

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestHelpDoesNotReturnEmptyUsage(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"create", "--help"},
		{"create", "-h"},
		{"prune", "--help"},
		{"rm", "--help"},
		{"completion", "--help"},
		{"daemon", "--help"},
		{"daemon", "log-level", "--help"},
		{"setup", "--help"},
	} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v exit=%d output=%q", args, code, out.String())
		}
		if strings.TrimSpace(out.String()) == "" {
			t.Fatalf("%v produced empty help", args)
		}
		if !strings.Contains(out.String(), "usage:") && !strings.Contains(out.String(), "Usage:") {
			t.Fatalf("%v output=%q", args, out.String())
		}
	}
}

func TestHelpSubcommandPrintsCommandUsage(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{command: "run", want: "usage: rsbx run"},
		{command: "rm", want: "usage: rsbx rm"},
		{command: "ls", want: "usage: rsbx ls"},
		{command: "stop", want: "usage: rsbx stop"},
		{command: "version", want: "usage: rsbx version"},
		{command: "policy", want: "Usage: rsbx policy"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			var out bytes.Buffer
			runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
			if code := runner.Run(context.Background(), []string{"help", tt.command}); code != 0 {
				t.Fatalf("exit=%d output=%q", code, out.String())
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Fatalf("help %s output=%q", tt.command, out.String())
			}
		})
	}
}

func TestHelpWithoutCommandPrintsTopLevelUsage(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
	if code := runner.Run(context.Background(), []string{"help"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out.String(), "Sandbox commands:") || !strings.Contains(out.String(), "--socket PATH") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestRootHelpListsCommandsAndSocket(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"--help"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	for _, want := range []string{"Sandbox commands:", "run", "create", "--socket"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help missing %q: %q", want, out.String())
		}
	}
}
