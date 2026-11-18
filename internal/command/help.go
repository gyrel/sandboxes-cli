package command

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// commandFlagHelp describes one flag row in a help section.
type commandFlagHelp struct {
	Short       string
	Name        string
	Value       string
	Description string
}

// commandSummary describes one entry in the Available Commands section.
type commandSummary struct {
	Name        string
	Description string
}

// commandHelp is the shared, structured source for every command's --help.
// Empty sections are omitted by renderCommandHelp.
type commandHelp struct {
	Description       []string
	Usage             []string
	Aliases           []string
	Examples          []string
	AvailableCommands []commandSummary
	Flags             []commandFlagHelp
	GlobalFlags       []commandFlagHelp
	Footer            string
}

// globalHelpFlags is the global section shared by every command.
func globalHelpFlags() []commandFlagHelp {
	return []commandFlagHelp{
		{Short: "D", Name: "debug", Description: "Enable debug logging (structured events on stderr)"},
		{
			Name:        "socket",
			Value:       "PATH",
			Description: "Local daemon endpoint",
		},
	}
}

// renderCommandHelp writes the reference help layout. Sections are separated by
// one blank line, description/usage/example lines are indented by two spaces,
// and flags are aligned in a two-column tabwriter table.
func renderCommandHelp(out io.Writer, spec commandHelp) error {
	if len(spec.GlobalFlags) == 0 {
		spec.GlobalFlags = globalHelpFlags()
	}
	var b strings.Builder
	writeTextSection(&b, "Description:", spec.Description)
	writeTextSection(&b, "Usage:", spec.Usage)
	writeTextSection(&b, "Aliases:", spec.Aliases)
	writeTextSection(&b, "Examples:", spec.Examples)
	writeCommandSection(&b, spec.AvailableCommands)
	writeFlagSection(&b, "Flags:", spec.Flags)
	writeFlagSection(&b, "Global Flags:", spec.GlobalFlags)
	if spec.Footer != "" {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(spec.Footer)
		b.WriteByte('\n')
	}
	if b.Len() == 0 {
		return nil
	}
	_, err := io.WriteString(out, b.String())
	return err
}

func startHelpSection(b *strings.Builder, title string) {
	if b.Len() > 0 {
		b.WriteByte('\n')
	}
	b.WriteString(title)
	b.WriteByte('\n')
}

func writeTextSection(b *strings.Builder, title string, lines []string) {
	if len(lines) == 0 {
		return
	}
	startHelpSection(b, title)
	for _, line := range lines {
		if line == "" {
			b.WriteByte('\n')
			continue
		}
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
}

func writeCommandSection(b *strings.Builder, commands []commandSummary) {
	if len(commands) == 0 {
		return
	}
	startHelpSection(b, "Available Commands:")
	tw := tabwriter.NewWriter(b, 0, 0, 3, ' ', 0)
	for _, command := range commands {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\n", command.Name, command.Description)
	}
	_ = tw.Flush()
}

func writeFlagSection(b *strings.Builder, title string, flags []commandFlagHelp) {
	if len(flags) == 0 {
		return
	}
	startHelpSection(b, title)
	tw := tabwriter.NewWriter(b, 0, 0, 3, ' ', 0)
	for _, flag := range flags {
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", formatFlagHelp(flag), flag.Description)
	}
	_ = tw.Flush()
}

func formatFlagHelp(flag commandFlagHelp) string {
	cell := "      --" + flag.Name
	if flag.Short != "" {
		cell = "  -" + flag.Short + ", --" + flag.Name
	}
	if flag.Value != "" {
		cell += " " + flag.Value
	}
	return cell
}

// showCommandHelp renders spec and reports write failures through the shared
// error path. Help never contacts the daemon.
func (r *Runner) showCommandHelp(spec commandHelp) int {
	if err := renderCommandHelp(r.Out, spec); err != nil {
		r.error(err)
		return 1
	}
	return 0
}
