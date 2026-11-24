package kit

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxArgumentsFileBytes = 1 << 20

// CollectArguments merges kit argument files and then --kit-arg values. Flag
// values override file values.
func CollectArguments(files, values []string) (map[string]string, error) {
	collected := make(map[string]string, len(values))
	for _, file := range files {
		fromFile, err := ReadArgumentsFile(file)
		if err != nil {
			return nil, err
		}
		maps.Copy(collected, fromFile)
	}
	for _, item := range values {
		key, value, err := parseArgumentPair(item)
		if err != nil {
			return nil, err
		}
		collected[key] = value
	}
	return collected, nil
}

// ReadArgumentsFile reads a regular file of name=value lines, or a YAML or
// JSON map of scalar values. Blank lines and # comments are ignored in line
// form.
func ReadArgumentsFile(path string) (map[string]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read kit arguments file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("kit arguments file must be a regular file")
	}
	if info.Size() > maxArgumentsFileBytes {
		return nil, fmt.Errorf("kit arguments file exceeds %d KiB", maxArgumentsFileBytes>>10)
	}
	file, err := os.Open(path) // #nosec G304 -- user-selected kit arguments file
	if err != nil {
		return nil, fmt.Errorf("read kit arguments file: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxArgumentsFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read kit arguments file: %w", err)
	}
	return parseArgumentsFile(data)
}

func parseArgumentsFile(data []byte) (map[string]string, error) {
	if len(data) > maxArgumentsFileBytes {
		return nil, fmt.Errorf("kit arguments file exceeds %d KiB", maxArgumentsFileBytes>>10)
	}
	lines := meaningfulLines(string(data))
	if len(lines) > 0 && (strings.HasPrefix(lines[0], "{") || !allContainEquals(lines)) {
		return parseArgumentsMapping(data)
	}
	values := make(map[string]string, len(lines))
	for _, line := range lines {
		key, value, err := parseArgumentPair(line)
		if err != nil {
			return nil, err
		}
		values[key] = value
	}
	return values, nil
}

func meaningfulLines(text string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

func allContainEquals(lines []string) bool {
	for _, line := range lines {
		if !strings.Contains(line, "=") {
			return false
		}
	}
	return true
}

func parseArgumentsMapping(data []byte) (map[string]string, error) {
	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, errors.New("kit arguments file must contain name=value lines or a YAML/JSON map")
	}
	values := make(map[string]string, len(raw))
	for key := range raw {
		node := raw[key]
		if !validArgumentKey(key) || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
			return nil, fmt.Errorf("kit arguments file entry %q must map a name to a scalar value", key)
		}
		values[key] = node.Value
	}
	return values, nil
}

// parseArgumentPair splits one name=value item. A key of the form kit.name
// targets only the kit called kit; the split is on the last dot because
// argument names cannot contain dots but kit names may.
func parseArgumentPair(item string) (string, string, error) {
	key, value, ok := strings.Cut(item, "=")
	if !ok || !validArgumentKey(key) {
		return "", "", errors.New("kit argument must use name=value or kit.name=value syntax")
	}
	return key, value, nil
}

func validArgumentKey(key string) bool {
	name := key
	if index := strings.LastIndex(key, "."); index >= 0 {
		if strings.ContainsAny(key[:index], " \t") || index == 0 {
			return false
		}
		name = key[index+1:]
	}
	return v3ArgKeyPattern.MatchString(name)
}

// ResolveArgumentValues checks arguments against the kit's v3 declarations and
// returns the value each declared argument takes, with defaults applied. It
// reports arguments the kit does not declare, required arguments that are
// missing, and values outside an argument's enum or pattern. Kits without a
// v3 args block declare nothing. Values must not be used when violations are
// returned.
func ResolveArgumentValues(doc Kit, kitName, specPath string, arguments map[string]string) (map[string]string, []Violation) {
	var declared map[string]V3Arg
	if doc.V3 != nil {
		declared = doc.V3.Args
	}
	supplied, violations := resolveArguments(kitName, specPath, declared, arguments)
	names := sortedArgumentNames(declared)
	resolved := make(map[string]string, len(declared))
	for _, name := range names {
		arg := declared[name]
		value, given := supplied[name]
		if !given && arg.HasDefault {
			value, given = arg.Default, true
		}
		if !given {
			if arg.Required {
				violations = append(violations, Violation{Path: specPath, Message: fmt.Sprintf("required kit argument %q is not set", name)})
			}
			continue
		}
		resolved[name] = value
		if problem := argumentValueProblem(arg, value); problem != "" {
			violations = append(violations, Violation{Path: specPath, Message: fmt.Sprintf("kit argument %q %s", name, problem)})
		}
	}
	return resolved, violations
}

// ArgumentEnvironment returns NAME=VALUE entries for the resolved values of
// arguments that deliver through env. It refuses build-delivered arguments
// (buildArg and buildSecret) because building kits needs a kit builder, and it
// never drops them silently. Error messages name arguments but never values.
func ArgumentEnvironment(doc Kit, values map[string]string) ([]string, error) {
	if doc.V3 == nil {
		return nil, nil
	}
	var entries []string
	owners := make(map[string]string)
	for _, name := range sortedArgumentNames(doc.V3.Args) {
		arg := doc.V3.Args[name]
		if arg.BuildArg != "" || arg.BuildSecret != "" {
			return nil, fmt.Errorf("kit argument %q is a build argument; building kits is not implemented", name)
		}
		value, resolved := values[name]
		if arg.Env == "" || !resolved {
			continue
		}
		if !v3ArgKeyPattern.MatchString(arg.Env) {
			return nil, fmt.Errorf("kit argument %q declares an invalid env name", name)
		}
		if owner, taken := owners[arg.Env]; taken {
			return nil, fmt.Errorf("kit arguments %q and %q both set env %s", owner, name, arg.Env)
		}
		owners[arg.Env] = name
		entries = append(entries, arg.Env+"="+value)
	}
	return entries, nil
}

func sortedArgumentNames(declared map[string]V3Arg) []string {
	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// resolveArguments maps supplied keys onto declared names. Unqualified keys
// apply to every kit and are applied first, so kit.name keys override them.
func resolveArguments(kitName, specPath string, declared map[string]V3Arg, arguments map[string]string) (map[string]string, []Violation) {
	keys := make([]string, 0, len(arguments))
	for key := range arguments {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		qi, qj := strings.Contains(keys[i], "."), strings.Contains(keys[j], ".")
		if qi != qj {
			return !qi
		}
		return keys[i] < keys[j]
	})
	values := make(map[string]string, len(arguments))
	var violations []Violation
	for _, key := range keys {
		name := key
		if index := strings.LastIndex(key, "."); index >= 0 {
			if key[:index] != kitName {
				violations = append(violations, Violation{Path: specPath, Message: fmt.Sprintf("kit argument %q is for kit %q, not this kit", key, key[:index])})
				continue
			}
			name = key[index+1:]
		}
		if _, ok := declared[name]; !ok {
			violations = append(violations, Violation{Path: specPath, Message: fmt.Sprintf("kit argument %q is not declared by this kit", key)})
			continue
		}
		values[name] = arguments[key]
	}
	return values, violations
}

func argumentValueProblem(arg V3Arg, value string) string {
	if len(arg.Enum) > 0 && !slices.Contains(arg.Enum, value) {
		return "is not one of its allowed values"
	}
	if arg.Pattern == "" {
		return ""
	}
	compiled, err := regexp.Compile(arg.Pattern)
	if err != nil {
		return "has an invalid pattern"
	}
	match := compiled.FindStringIndex(value)
	if len(match) != 2 || match[0] != 0 || match[1] != len(value) {
		return "does not match its pattern"
	}
	return ""
}
