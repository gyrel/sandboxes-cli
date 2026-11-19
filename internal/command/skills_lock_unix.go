//go:build darwin || linux

package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// acquireSkillsLock serializes store transactions between cooperating CLI
// processes. The directory itself is locked so no removable lock file can be
// replaced to obtain a second independent lock. This advisory lock is released
// on process exit; it does not recover a transaction interrupted by a crash,
// prevent external store-directory replacement, or coordinate older clients.
func acquireSkillsLock(ctx context.Context, root *os.Root) (*os.File, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("skills: open store lock: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			_ = dir.Close()
			return nil, fmt.Errorf("skills: acquire store lock: %w", err)
		}
		err = unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			_ = dir.Close()
			return nil, fmt.Errorf("skills: acquire store lock: %w", err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = dir.Close()
			return nil, fmt.Errorf("skills: acquire store lock: %w", ctx.Err())
		case <-timer.C:
		}
	}
}
