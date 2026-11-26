package kit

import "sync"

const (
	// APIVersion is the current kit apiVersion. The CLI writes it for every new
	// output (packed archives and generated specs).
	APIVersion = "gyrel.dev/v1alpha1"

	// APIVersionLegacy is the pre-rename apiVersion accepted on read for alpha
	// continuity. Kits carrying it are normalized to APIVersion on write.
	APIVersionLegacy = "rheic.dev/v1alpha1"
)

// LegacyAPIVersionWarning is the user-facing deprecation line emitted once per
// command when a kit written before the Gyrel rename is read.
const LegacyAPIVersionWarning = "apiVersion " + APIVersionLegacy + " is deprecated; repack with " + APIVersion

// validAPIVersion reports whether version is the current apiVersion or the
// pre-rename legacy value accepted for alpha continuity.
func validAPIVersion(version string) bool {
	return version == APIVersion || version == APIVersionLegacy
}

var (
	deprecationMu      sync.Mutex
	deprecationPending bool
)

// markLegacyAPIVersion records that a legacy apiVersion was read. It is
// idempotent per command so repeated reads collapse into one warning.
func markLegacyAPIVersion() {
	deprecationMu.Lock()
	deprecationPending = true
	deprecationMu.Unlock()
}

// ResetDeprecations clears the once-per-command deprecation state. The CLI
// calls it at the start of each command so a reused process never carries a
// stale warning across invocations.
func ResetDeprecations() {
	deprecationMu.Lock()
	deprecationPending = false
	deprecationMu.Unlock()
}

// ConsumeDeprecations returns the pending deprecation warning, if any, and
// clears it so it is emitted at most once per command.
func ConsumeDeprecations() string {
	deprecationMu.Lock()
	defer deprecationMu.Unlock()
	if !deprecationPending {
		return ""
	}
	deprecationPending = false
	return LegacyAPIVersionWarning
}
