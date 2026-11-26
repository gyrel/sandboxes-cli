package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"gopkg.in/yaml.v3"
)

const skillsUsage = `Usage: rsbx skills COMMAND

Experimental host-side agent skills store. Gyrel keeps imported skills in its
own config directory, never inside a sandbox workspace or Docker state.

Commands:
  add REPOSITORY  add skills from a Git repository (https URL, owner/repository or local directory)
  ls, list        list skills imported by Gyrel
  import [PATH]   import from supported host directories or one local directory
  rm, remove      remove a skill imported by Gyrel
  update [NAME]   update skills added from a repository

Import requires PATH to be a real directory containing SKILL.md with YAML
frontmatter fields "name" and "description". Symlinks, special files, unsafe
names and oversized trees are rejected. Re-importing identical content is a
no-op; replacing changed content requires --force.
`

const skillsListUsage = "usage: rsbx skills ls [--format table|json|yaml | --json | --quiet]"

type skillsListOutput struct {
	Store  string             `json:"store" yaml:"store"`
	Skills []skillsListRecord `json:"skills" yaml:"skills"`
}

type skillsListRecord struct {
	Name       string `json:"name" yaml:"name"`
	Source     string `json:"source" yaml:"source"`
	ImportedAt string `json:"imported_at" yaml:"imported_at"`
}

func (r *Runner) skills(ctx context.Context, args []string) int {
	args, code, done := r.prepareFamilyArgs(skillsCommand, args)
	if done {
		return code
	}
	if len(args) == 0 || args[0] == helpCommand || args[0] == helpShort || args[0] == helpFlag {
		return r.showCommandHelp(skillsHelp())
	}
	switch args[0] {
	case helpNameAdd, "a":
		return r.addSkills(ctx, args[1:])
	case "ls", commandList:
		return r.listSkills(args[1:])
	case commandImport:
		return r.importSkills(ctx, args[1:])
	case "rm", commandRemove:
		return r.removeSkills(ctx, args[1:])
	case "update", "upgrade":
		return r.updateSkills(ctx, args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "rsbx skills: unknown subcommand %q\n", args[0])
		_, _ = fmt.Fprint(r.Err, skillsUsage)
		return 2
	}
}

func (r *Runner) listSkills(args []string) int {
	fs := r.newFlagSet("skills ls")
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	quiet := fs.Bool("quiet", false, "only display skill names")
	fs.BoolVar(quiet, "q", false, "only display skill names")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return r.showCommandHelp(skillsListHelp())
		}
		return r.flagParseFailure("skills ls", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, skillsListUsage)
		return 2
	}
	selected, err := skillsListFormat(*format, *jsonOutput, *quiet)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx skills ls: %v\n", err)
		return 2
	}
	report, err := readSkillsList()
	if err != nil {
		r.error(err)
		return 1
	}
	if err := renderSkillsList(r.Out, report, selected, *quiet); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func skillsListFormat(format string, jsonOutput, quiet bool) (string, error) {
	if quiet && (jsonOutput || format != listFormatTable) {
		return "", errors.New("--quiet cannot be combined with --json or an explicit --format")
	}
	return resolveOperationFormat(format, jsonOutput)
}

func readSkillsList() (skillsListOutput, error) {
	paths, err := resolveSkillsPaths()
	if err != nil {
		return skillsListOutput{}, err
	}
	report := skillsListOutput{Store: paths.store, Skills: []skillsListRecord{}}
	root, err := openSkillsRoot(paths, false)
	if errors.Is(err, errSkillsRootMissing) {
		return report, nil
	}
	if err != nil {
		return skillsListOutput{}, err
	}
	defer func() { _ = root.Close() }()
	registry, err := readSkillsRegistry(root)
	if err != nil {
		return skillsListOutput{}, err
	}
	report.Skills = skillsListRecords(registry)
	return report, nil
}

func skillsListRecords(registry skillsRegistry) []skillsListRecord {
	records := make([]skillsListRecord, 0, len(registry.Skills))
	for _, entry := range registry.Skills {
		records = append(records, skillsListRecord{
			Name:       entry.Name,
			Source:     entry.Source,
			ImportedAt: entry.ImportedAt,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	return records
}

func renderSkillsList(out io.Writer, report skillsListOutput, format string, quiet bool) error {
	if quiet {
		for _, record := range report.Skills {
			if _, err := fmt.Fprintln(out, record.Name); err != nil {
				return err
			}
		}
		return nil
	}
	switch format {
	case listFormatJSON:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case listFormatYAML:
		data, err := yaml.Marshal(report)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		return writeSkillsTable(out, report)
	}
}

func writeSkillsTable(out io.Writer, report skillsListOutput) error {
	if len(report.Skills) == 0 {
		_, err := fmt.Fprintf(out, "No skills imported in %s\n", report.Store)
		return err
	}
	writer := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	if _, err := fmt.Fprintln(writer, "SKILL\tSOURCE\tIMPORTED"); err != nil {
		return err
	}
	for _, record := range report.Skills {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\n", safeSkillText(record.Name), safeSkillText(record.Source), safeSkillText(record.ImportedAt)); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func unsafeSkillRune(value rune) bool {
	return unicode.IsControl(value) || value == '\u2028' || value == '\u2029'
}

func safeSkillText(value string) string {
	return strings.Map(func(value rune) rune {
		if unsafeSkillRune(value) {
			return ' '
		}
		return value
	}, value)
}
