package command

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

type skillTreeEntry struct {
	Rel  string
	Dir  bool
	Mode fs.FileMode
	Size int64
	Info fs.FileInfo
}

type skillWalkState struct {
	entries int
	bytes   int64
}

func collectSkillEntries(root *os.Root) ([]skillTreeEntry, error) {
	entries := make([]skillTreeEntry, 0)
	state := skillWalkState{}
	if err := walkSkillDirectory(root, ".", nil, 0, &state, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func walkSkillDirectory(root *os.Root, rel string, expected fs.FileInfo, depth int, state *skillWalkState, entries *[]skillTreeEntry) error {
	directory, err := openCopySource(root, rel)
	if err != nil {
		return errors.New("skills: cannot open source directory")
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || (expected != nil && !os.SameFile(expected, info)) {
		_ = directory.Close()
		return errors.New("skills: source path must be a real directory")
	}
	children, readErr := directory.ReadDir(maxSkillTreeEntries - state.entries + 1)
	closeErr := directory.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil {
		return errors.New("skills: cannot read source directory")
	}
	if len(children) > maxSkillTreeEntries-state.entries {
		return errors.New("skills: source tree has too many entries")
	}
	for _, child := range children {
		childRel := child.Name()
		if rel != "." {
			childRel = filepath.Join(rel, child.Name())
		}
		if err := walkSkillEntry(root, childRel, depth, state, entries); err != nil {
			return err
		}
	}
	return nil
}

func walkSkillEntry(root *os.Root, rel string, depth int, state *skillWalkState, entries *[]skillTreeEntry) error {
	info, err := root.Lstat(rel)
	if err != nil {
		return errors.New("skills: cannot inspect source entry")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("skills: source entry %q is a symbolic link", filepath.Base(rel))
	}
	state.entries++
	if state.entries > maxSkillTreeEntries {
		return errors.New("skills: source tree has too many entries")
	}
	if info.IsDir() {
		if depth+1 > maxSkillTreeDepth {
			return errors.New("skills: source tree is nested too deeply")
		}
		*entries = append(*entries, skillTreeEntry{Rel: rel, Dir: true, Mode: info.Mode().Perm()})
		return walkSkillDirectory(root, rel, info, depth+1, state, entries)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("skills: source entry %q is not a regular file", filepath.Base(rel))
	}
	if err := rejectCopyHardlink(info); err != nil {
		return fmt.Errorf("skills: source file %q: %w", filepath.Base(rel), err)
	}
	if info.Size() > maxSkillFileBytes {
		return fmt.Errorf("skills: source file %q exceeds the per-file limit", filepath.Base(rel))
	}
	state.bytes += info.Size()
	if state.bytes > maxSkillTreeBytes {
		return errors.New("skills: source tree exceeds the total size limit")
	}
	*entries = append(*entries, skillTreeEntry{Rel: rel, Mode: info.Mode().Perm(), Size: info.Size(), Info: info})
	return nil
}

func copySkillTree(source *os.Root, entries []skillTreeEntry, stage *os.Root) error {
	for _, entry := range entries {
		if entry.Dir {
			if err := stage.Mkdir(entry.Rel, 0o700); err != nil {
				return fmt.Errorf("skills: stage directory: %w", err)
			}
			continue
		}
		if err := copySkillFile(source, stage, entry); err != nil {
			return err
		}
	}
	return nil
}

func copySkillFile(source *os.Root, stage *os.Root, entry skillTreeEntry) error {
	input, err := openCopySource(source, entry.Rel)
	if err != nil {
		return errors.New("skills: cannot open source file")
	}
	info, err := input.Stat()
	if err != nil || !skillFileMatches(entry, info, true) {
		_ = input.Close()
		return fmt.Errorf("skills: source file %q changed during import", filepath.Base(entry.Rel))
	}
	if err := rejectCopyHardlink(info); err != nil {
		_ = input.Close()
		return fmt.Errorf("skills: source file %q: %w", filepath.Base(entry.Rel), err)
	}
	mode := fs.FileMode(0o644)
	if entry.Mode&0o111 != 0 {
		mode = 0o755
	}
	output, err := stage.OpenFile(entry.Rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		_ = input.Close()
		return fmt.Errorf("skills: stage source file %q: %w", filepath.Base(entry.Rel), err)
	}
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, digest), io.LimitReader(input, maxSkillFileBytes+1))
	closeErr := output.Close()
	checkErr := verifySkillSourceCopy(input, info, digest.Sum(nil), entry.Size)
	inputErr := input.Close()
	if copyErr != nil || inputErr != nil || closeErr != nil || checkErr != nil || written != entry.Size {
		return fmt.Errorf("skills: copy source file %q failed", filepath.Base(entry.Rel))
	}
	return nil
}

func skillFileMatches(entry skillTreeEntry, info fs.FileInfo, checkTime bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() != entry.Size || entry.Info == nil || !os.SameFile(entry.Info, info) {
		return false
	}
	return !checkTime || info.ModTime().Equal(entry.Info.ModTime())
}

func verifySkillSourceCopy(input *os.File, before fs.FileInfo, expected []byte, size int64) error {
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return err
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(input, maxSkillFileBytes+1))
	if err != nil || written != size || !bytes.Equal(expected, digest.Sum(nil)) {
		return errors.New("skills: source changed during copy")
	}
	after, err := input.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != size || !after.ModTime().Equal(before.ModTime()) {
		return errors.New("skills: source changed during copy")
	}
	return rejectCopyHardlink(after)
}

func hashSkillEntries(root *os.Root, entries []skillTreeEntry) (string, error) {
	digest := sha256.New()
	for _, entry := range entries {
		header := fmt.Sprintf("%s\x00%t\x00%o\x00%d\x00", entry.Rel, entry.Dir, entry.Mode.Perm(), entry.Size)
		if _, err := digest.Write([]byte(header)); err != nil {
			return "", err
		}
		if entry.Dir {
			continue
		}
		if err := hashSkillFile(root, entry, digest); err != nil {
			return "", err
		}
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func hashSkillFile(root *os.Root, entry skillTreeEntry, digest io.Writer) error {
	file, err := openCopySource(root, entry.Rel)
	if err != nil {
		return errors.New("skills: cannot open stored skill file")
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !skillFileMatches(entry, info, false) {
		return fmt.Errorf("skills: stored skill file %q changed", filepath.Base(entry.Rel))
	}
	if err := rejectCopyHardlink(info); err != nil {
		return fmt.Errorf("skills: stored skill file %q: %w", filepath.Base(entry.Rel), err)
	}
	if _, err := io.CopyN(digest, file, entry.Size); err != nil {
		return fmt.Errorf("skills: hash stored skill file %q: %w", filepath.Base(entry.Rel), err)
	}
	return nil
}

func installedSkillDigest(store *os.Root, name string) (string, error) {
	info, err := store.Lstat(name)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("skills: %q is not a real directory", name)
	}
	skillRoot, err := store.OpenRoot(name)
	if err != nil {
		return "", errors.New("skills: cannot open stored skill")
	}
	opened, err := skillRoot.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = skillRoot.Close()
		return "", errors.New("skills: stored skill changed while opening")
	}
	entries, err := collectSkillEntries(skillRoot)
	if err != nil {
		_ = skillRoot.Close()
		return "", errors.New("skills: cannot inspect stored skill")
	}
	digest, hashErr := hashSkillEntries(skillRoot, entries)
	closeErr := skillRoot.Close()
	if hashErr != nil || closeErr != nil {
		return "", errors.New("skills: cannot inspect stored skill")
	}
	return digest, nil
}

func createSkillStage(store *os.Root) (string, *os.Root, error) {
	for range 3 {
		name, err := randomSkillHiddenName(".import-")
		if err != nil {
			return "", nil, err
		}
		if err := store.Mkdir(name, 0o700); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return "", nil, fmt.Errorf("skills: create staging directory: %w", err)
		}
		root, err := openSkillStage(store, name)
		if err != nil {
			_ = store.Remove(name)
			return "", nil, err
		}
		return name, root, nil
	}
	return "", nil, errors.New("skills: cannot allocate staging directory")
}

func openSkillStage(store *os.Root, name string) (*os.Root, error) {
	info, err := store.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("skills: staging directory changed")
	}
	root, err := store.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("skills: open staging directory: %w", err)
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, errors.New("skills: staging directory changed while opening")
	}
	return root, nil
}

func removeSkillStage(store *os.Root, name string) {
	_ = store.RemoveAll(name)
}
