package kit

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Artifact bounds match the skills tree limits so local kit directories and
// ZIP archives are capped the same way across the CLI.
const (
	kitSpecFile          = "spec.yaml"
	maxArtifactEntries   = 1000
	maxArtifactDepth     = 16
	maxArtifactBytes     = 8 << 20
	maxArtifactFileBytes = 1 << 20
)

// Violation is one reason a kit artifact is invalid. Path is relative to the
// artifact root and empty for problems that concern the root itself, so host
// paths never appear in output.
type Violation struct {
	Path    string `json:"path,omitempty" yaml:"path,omitempty"`
	Message string `json:"message" yaml:"message"`
}

func (v Violation) String() string {
	if v.Path == "" {
		return v.Message
	}
	return v.Path + ": " + v.Message
}

// ViolationError reports a kit that failed offline validation.
type ViolationError struct {
	Violations []Violation
}

func (e *ViolationError) Error() string {
	parts := make([]string, 0, len(e.Violations))
	for _, violation := range e.Violations {
		parts = append(parts, violation.String())
	}
	return strings.Join(parts, "; ")
}

// Entry is one regular file or directory inside a kit artifact. Name is
// slash-separated and relative to the artifact root.
type Entry struct {
	Name string
	Dir  bool
	Size int64
	Exec bool

	path string
	info fs.FileInfo
}

// Result is the offline view of one local kit artifact. Violations and
// Entries are sorted so output is stable across hosts.
type Result struct {
	Name       string
	Kind       string
	Entries    []Entry
	Violations []Violation
}

// Validate checks a local kit directory or ZIP file without a daemon.
// Content problems are returned as Violations; err is reserved for references
// that cannot be read at all.
func Validate(reference string, arguments map[string]string) (Result, error) {
	info, err := os.Stat(reference)
	if err != nil {
		return Result{}, fmt.Errorf("inspect kit reference: %w", err)
	}
	switch {
	case info.IsDir():
		return validateDirectory(reference, arguments)
	case info.Mode().IsRegular() && strings.EqualFold(filepath.Ext(reference), ".zip"):
		return validateArchive(reference, info, arguments)
	default:
		return Result{}, errors.New("kit reference must be a local directory or .zip file")
	}
}

// IsGitReference reports whether reference looks like a git repository URL
// or SCP-style address. An existing local path always wins.
func IsGitReference(reference string) bool {
	if _, err := os.Stat(reference); err == nil {
		return false
	}
	for _, scheme := range []string{"https://", "http://", "ssh://", "git://"} {
		if strings.HasPrefix(reference, scheme) {
			return true
		}
	}
	return strings.HasPrefix(reference, "git@") && strings.Contains(reference, ":")
}

// artifact is the format-neutral view that directory and ZIP validation share.
type artifact struct {
	name       string
	entries    []Entry
	violations []Violation
	open       func(rel string) (io.ReadCloser, error)
}

func validateDirectory(reference string, arguments map[string]string) (Result, error) {
	root, err := filepath.Abs(reference)
	if err != nil {
		return Result{}, fmt.Errorf("resolve kit directory: %w", err)
	}
	scan := &artifactScan{}
	scan.walk(root, "", 0)
	return artifact{
		name:       filepath.Base(root),
		entries:    scan.sortedEntries(),
		violations: scan.violations,
		open: func(rel string) (io.ReadCloser, error) {
			return os.Open(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- entry from a scan of the user-selected kit directory
		},
	}.validate(arguments), nil
}

func validateArchive(reference string, info fs.FileInfo, arguments map[string]string) (Result, error) {
	if info.Size() > 2*maxArtifactBytes {
		return Result{}, fmt.Errorf("kit archive exceeds %d MiB", (2*maxArtifactBytes)>>20)
	}
	reader, err := zip.OpenReader(reference)
	if err != nil {
		return Result{}, fmt.Errorf("read kit archive: %w", err)
	}
	defer func() { _ = reader.Close() }()
	scan := &artifactScan{}
	files := scan.archive(&reader.Reader)
	return artifact{
		name:       strings.TrimSuffix(filepath.Base(reference), filepath.Ext(reference)),
		entries:    scan.sortedEntries(),
		violations: scan.violations,
		open: func(rel string) (io.ReadCloser, error) {
			file, ok := files[rel]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return file.Open()
		},
	}.validate(arguments), nil
}

// validate parses the descriptor at the artifact root and checks arguments.
func (a artifact) validate(arguments map[string]string) Result {
	result := Result{Name: a.name, Entries: a.entries, Violations: append([]Violation(nil), a.violations...)}
	specName, found := findSpecEntry(a.name, a.entries)
	if !found {
		result.Violations = append(result.Violations, Violation{Message: "kit requires <name>.yaml, spec.yaml or spec.yml at its root"})
		return result.sorted()
	}
	doc, err := a.decode(specName)
	if err != nil {
		result.Violations = append(result.Violations, Violation{Path: specName, Message: err.Error()})
		return result.sorted()
	}
	result.Kind = doc.Kind
	if doc.V3 != nil {
		result.Kind = doc.V3.Kind
	} else if doc.Metadata.Name != "" {
		result.Name = doc.Metadata.Name
	}
	_, violations := ResolveArgumentValues(doc, result.Name, specName, arguments)
	result.Violations = append(result.Violations, violations...)
	return result.sorted()
}

func (a artifact) decode(specName string) (Kit, error) {
	reader, err := a.open(specName)
	if err != nil {
		return Kit{}, fmt.Errorf("open kit: %w", err)
	}
	defer func() { _ = reader.Close() }()
	return Decode(reader)
}

func (r Result) sorted() Result {
	sort.SliceStable(r.Violations, func(i, j int) bool {
		if r.Violations[i].Path != r.Violations[j].Path {
			return r.Violations[i].Path < r.Violations[j].Path
		}
		return r.Violations[i].Message < r.Violations[j].Message
	})
	return r
}

// kitSpecNames lists the root descriptor names accepted for a kit, in order.
// The stem-named form is the Docker kit v3 layout; spec.yaml is Gyrel's.
func kitSpecNames(stem string) []string {
	return []string{stem + ".yaml", stem + ".yml", kitSpecFile, "spec.yml"}
}

func findSpecEntry(stem string, entries []Entry) (string, bool) {
	files := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !entry.Dir {
			files[entry.Name] = true
		}
	}
	for _, name := range kitSpecNames(stem) {
		if files[name] {
			return name, true
		}
	}
	return "", false
}

// artifactScan collects entries under the shared count, depth and size bounds.
// Rejected paths become violations; the scan stops once a bound is exceeded.
type artifactScan struct {
	entries    []Entry
	violations []Violation
	bytes      int64
	halted     bool
}

func (s *artifactScan) reject(rel, message string) {
	s.violations = append(s.violations, Violation{Path: rel, Message: message})
}

func (s *artifactScan) accept(entry Entry) {
	if len(s.entries) >= maxArtifactEntries {
		s.reject("", fmt.Sprintf("kit has more than %d entries", maxArtifactEntries))
		s.halted = true
		return
	}
	if !entry.Dir {
		s.bytes += entry.Size
		if s.bytes > maxArtifactBytes {
			s.reject("", fmt.Sprintf("kit exceeds %d MiB", maxArtifactBytes>>20))
			s.halted = true
			return
		}
		if entry.Size > maxArtifactFileBytes {
			s.reject(entry.Name, fmt.Sprintf("file exceeds %d MiB", maxArtifactFileBytes>>20))
		}
	}
	s.entries = append(s.entries, entry)
}

func (s *artifactScan) sortedEntries() []Entry {
	sort.SliceStable(s.entries, func(i, j int) bool { return s.entries[i].Name < s.entries[j].Name })
	return s.entries
}

func (s *artifactScan) walk(root, rel string, depth int) {
	children, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		s.reject(rel, "cannot read directory")
		return
	}
	for _, child := range children {
		if s.halted {
			return
		}
		s.visit(root, path.Join(rel, child.Name()), child, depth)
	}
}

func (s *artifactScan) visit(root, rel string, child fs.DirEntry, depth int) {
	if strings.ContainsRune(child.Name(), '\\') {
		s.reject(rel, "file name contains a backslash")
		return
	}
	mode := child.Type()
	switch {
	case mode&fs.ModeSymlink != 0:
		s.reject(rel, "symbolic links are not allowed in kit artifacts")
	case child.IsDir():
		if depth+1 > maxArtifactDepth {
			s.reject(rel, fmt.Sprintf("directory nesting exceeds %d levels", maxArtifactDepth))
			return
		}
		s.accept(Entry{Name: rel, Dir: true, path: filepath.Join(root, filepath.FromSlash(rel))})
		s.walk(root, rel, depth+1)
	case mode.IsRegular():
		info, err := child.Info()
		if err != nil {
			s.reject(rel, "cannot inspect file")
			return
		}
		s.accept(Entry{Name: rel, Size: info.Size(), Exec: info.Mode().Perm()&0o111 != 0, path: filepath.Join(root, filepath.FromSlash(rel)), info: info})
	default:
		s.reject(rel, "only regular files and directories are allowed in kit artifacts")
	}
}

// archive scans ZIP entries and returns the regular files by name. Names are
// checked before anything is read so traversal, absolute and duplicate
// entries are refused without touching the host filesystem.
func (s *artifactScan) archive(reader *zip.Reader) map[string]*zip.File {
	files := make(map[string]*zip.File, len(reader.File))
	seen := make(map[string]bool, len(reader.File))
	if len(reader.File) > maxArtifactEntries {
		s.reject("", fmt.Sprintf("kit has more than %d entries", maxArtifactEntries))
		return files
	}
	for _, file := range reader.File {
		if s.halted {
			break
		}
		name, dir, ok := archiveEntryName(file.Name)
		if !ok {
			s.reject(file.Name, "archive entry name is unsafe")
			continue
		}
		if seen[name] {
			s.reject(name, "archive entry is duplicated")
			continue
		}
		seen[name] = true
		s.archiveEntry(file, name, dir, files)
	}
	return files
}

func (s *artifactScan) archiveEntry(file *zip.File, name string, dir bool, files map[string]*zip.File) {
	mode := file.Mode()
	switch {
	case mode&fs.ModeSymlink != 0:
		s.reject(name, "symbolic links are not allowed in kit artifacts")
	case dir:
		s.accept(Entry{Name: name, Dir: true})
	case mode.IsRegular():
		size := int64(min(file.UncompressedSize64, maxArtifactBytes+1))
		s.accept(Entry{Name: name, Size: size, Exec: mode.Perm()&0o111 != 0})
		if !s.halted {
			files[name] = file
		}
	default:
		s.reject(name, "only regular files and directories are allowed in kit artifacts")
	}
}

// archiveEntryName returns the canonical relative name of a ZIP entry. It
// refuses absolute paths, drive letters, backslashes, empty, "." and ".."
// segments, and any name that is not already clean.
func archiveEntryName(raw string) (string, bool, bool) {
	dir := strings.HasSuffix(raw, "/")
	name := strings.TrimSuffix(raw, "/")
	if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") {
		return "", false, false
	}
	if len(name) >= 2 && name[1] == ':' {
		return "", false, false
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", false, false
		}
	}
	if path.Clean(name) != name {
		return "", false, false
	}
	return name, dir, true
}
