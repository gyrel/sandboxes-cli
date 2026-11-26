package command

import (
	"os"
	"testing"
)

// TestMain isolates the shared-skills store and settings defaults from the
// developer's real config home. Since create/run resolve skills.defaultMode
// (readonly by default, like sbx), a default creation now touches
// XDG_CONFIG_HOME/rheic/skills on demand (legacy-compat dir name retained).
// Tests that need a specific config
// directory keep using t.Setenv, which overrides and restores this value.
func TestMain(m *testing.M) {
	// Respect any explicit XDG_CONFIG_HOME, including an empty value: tests
	// use t.Setenv("XDG_CONFIG_HOME", "") to force the HOME fallback, and
	// re-exec subprocesses must inherit exactly the parent's value.
	if _, ok := os.LookupEnv("XDG_CONFIG_HOME"); ok {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "gyrel-command-test-config")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("XDG_CONFIG_HOME", dir); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
