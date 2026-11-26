package kit

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// packTime pins every ZIP timestamp so packing the same tree yields the same
// bytes. 1980-01-01 is the earliest DOS timestamp.
var packTime = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// Packed describes a kit artifact written by Pack.
type Packed struct {
	Name   string
	Output string
	Files  int
}

// Pack validates the kit directory offline, then writes it to output as a
// deterministic ZIP. An empty output defaults to <kit-name>.zip in the working
// directory. Kits that need arguments are refused, because pack takes none.
func Pack(directory, output string) (Packed, error) {
	info, err := os.Stat(directory)
	if err != nil {
		return Packed{}, fmt.Errorf("inspect kit directory: %w", err)
	}
	if !info.IsDir() {
		return Packed{}, errors.New("kit pack expects a directory")
	}
	result, err := Validate(directory, nil)
	if err != nil {
		return Packed{}, err
	}
	violations := append(append([]Violation(nil), result.Violations...), packLayoutViolations(result.Entries)...)
	if len(violations) > 0 {
		return Packed{}, &ViolationError{Violations: violations}
	}
	if output == "" {
		if output, err = defaultPackOutput(result.Name); err != nil {
			return Packed{}, err
		}
	}
	if !strings.HasSuffix(output, ".zip") {
		return Packed{}, errors.New("kit pack output must end in .zip")
	}
	if _, err := os.Lstat(output); err == nil {
		return Packed{}, fmt.Errorf("output %s already exists", output)
	}
	members := packMembers(result.Entries)
	if err := writeArchive(output, members); err != nil {
		return Packed{}, err
	}
	return Packed{Name: result.Name, Output: output, Files: len(members)}, nil
}

func defaultPackOutput(name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return "", fmt.Errorf("kit name %q cannot be a default file name; pass --output", name)
	}
	return name + ".zip", nil
}

// packLayoutViolations enforces the packaged layout: spec.yaml at the root and
// an optional files/ directory. Anything else would be silently dropped or
// shipped unreviewed, so it is refused instead.
func packLayoutViolations(entries []Entry) []Violation {
	var violations []Violation
	hasSpec := false
	for _, entry := range entries {
		if strings.Contains(entry.Name, "/") {
			continue
		}
		switch {
		case entry.Name == kitSpecFile && !entry.Dir:
			hasSpec = true
		case entry.Name == "files" && entry.Dir:
		default:
			violations = append(violations, Violation{Path: entry.Name, Message: "not packaged; a kit artifact contains only spec.yaml and files/"})
		}
	}
	if !hasSpec {
		violations = append(violations, Violation{Path: kitSpecFile, Message: "kit pack requires spec.yaml at the kit root"})
	}
	return violations
}

func packMembers(entries []Entry) []Entry {
	members := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Dir || (entry.Name != kitSpecFile && !strings.HasPrefix(entry.Name, "files/")) {
			continue
		}
		members = append(members, entry)
	}
	return members
}

// writeArchive writes to a temporary file beside the target and renames it
// into place, so a failed pack never leaves a partial .zip behind.
func writeArchive(output string, members []Entry) error {
	parent := filepath.Dir(output)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temp, err := os.CreateTemp(parent, ".kit-pack-*.tmp")
	if err != nil {
		return fmt.Errorf("create kit archive: %w", err)
	}
	if err := writeZip(temp, members); err != nil {
		_ = temp.Close()
		_ = os.Remove(temp.Name())
		return err
	}
	if err := commitTemp(temp, output); err != nil {
		_ = os.Remove(temp.Name())
		return err
	}
	return nil
}

func commitTemp(temp *os.File, output string) error {
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set kit archive mode: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync kit archive: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close kit archive: %w", err)
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output %s already exists", output)
	}
	if err := os.Rename(temp.Name(), output); err != nil {
		return fmt.Errorf("write kit archive: %w", err)
	}
	return nil
}

func writeZip(file io.Writer, members []Entry) error {
	archive := zip.NewWriter(file)
	for _, member := range members {
		if err := writeZipMember(archive, member); err != nil {
			_ = archive.Close()
			return err
		}
	}
	if err := archive.Close(); err != nil {
		return fmt.Errorf("finish kit archive: %w", err)
	}
	return nil
}

func writeZipMember(archive *zip.Writer, member Entry) error {
	source, err := os.Open(member.path) // #nosec G304 -- member was scanned from the user-selected kit directory
	if err != nil {
		return fmt.Errorf("open kit file: %w", err)
	}
	defer func() { _ = source.Close() }()
	if err := verifyUnchanged(source, member); err != nil {
		return err
	}
	header := &zip.FileHeader{Name: member.Name, Method: zip.Deflate, Modified: packTime}
	mode := fs.FileMode(0o644)
	if member.Exec {
		mode = 0o755
	}
	header.SetMode(mode)
	writer, err := archive.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("add kit file: %w", err)
	}
	if member.Name == kitSpecFile {
		data, err := io.ReadAll(io.LimitReader(source, maxArtifactFileBytes+1))
		if err != nil {
			return fmt.Errorf("read kit file: %w", err)
		}
		if len(data) > maxArtifactFileBytes {
			return fmt.Errorf("file exceeds %d MiB", maxArtifactFileBytes>>20)
		}
		data = normalizeSpecAPIVersion(data)
		if _, err := writer.Write(data); err != nil {
			return fmt.Errorf("write kit file: %w", err)
		}
		return nil
	}
	written, err := io.Copy(writer, io.LimitReader(source, maxArtifactFileBytes+1))
	if err != nil {
		return fmt.Errorf("read kit file: %w", err)
	}
	if written > maxArtifactFileBytes {
		return fmt.Errorf("file exceeds %d MiB", maxArtifactFileBytes>>20)
	}
	return nil
}

// normalizeSpecAPIVersion rewrites a legacy apiVersion so every packed archive
// ships gyrel.dev/v1alpha1. It only touches the deprecated value; a canonical
// spec passes through unchanged.
func normalizeSpecAPIVersion(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte(APIVersionLegacy), []byte(APIVersion))
}

// verifyUnchanged refuses to pack a file that was swapped after the scan, for
// example for a symlink or a different inode at the same path.
func verifyUnchanged(source *os.File, member Entry) error {
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(member.info, info) {
		return errors.New("kit changed while packing; retry")
	}
	return nil
}
