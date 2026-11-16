package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

const (
	// runtimeProbeCommand is intentionally harmless. The probe only needs to
	// know whether the daemon can execute a guest command at all.
	runtimeProbeCommand = "true"
	// runtimeRollbackTimeout bounds restoring a sandbox after a start that the
	// daemon cannot back with a runtime.
	runtimeRollbackTimeout = 15 * time.Second
)

// requireRuntimeForStart fails a start that the daemon accepted but cannot back
// with a runtime backend. Older state-only daemons persist the running state
// before they discover that exec is unsupported, so the CLI probes with a
// harmless exec and restores the stopped state before returning an actionable
// error. A client without exec support is not treated as a state-only daemon.
func (r *Runner) requireRuntimeForStart(ctx context.Context, client sdk.Client, id, target string) error {
	_, err := sdk.ExecService(client).Exec(ctx, sdk.ExecRequest{
		SandboxID: id,
		Argv:      []string{runtimeProbeCommand},
		Stdout:    io.Discard,
		Stderr:    io.Discard,
	})
	if err == nil || !runtimeUnsupported(err) {
		return nil
	}
	probeErr := fmt.Errorf("cannot start sandbox %s: daemon has no runtime backend, so exec, cp and attach would fail. Start sandboxesd with a runtime backend (containerd/nerdbox) and retry", target)
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runtimeRollbackTimeout)
	defer cancel()
	if _, stopErr := client.Sandboxes().Stop(rollbackCtx, id, sdk.StopOptions{}); stopErr != nil {
		return errors.Join(probeErr, fmt.Errorf("restoring the stopped state failed: %w", stopErr))
	}
	return fmt.Errorf("%w; the sandbox was restored to stopped", probeErr)
}

// runtimeUnsupported reports whether the daemon refused an operation because no
// runtime backend implements it. Client-side capability gaps are not runtime
// failures: a fake or reduced client without exec must still be able to start.
func runtimeUnsupported(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "exec is not supported by this client") {
		return false
	}
	return strings.Contains(message, "runtime does not support exec")
}
