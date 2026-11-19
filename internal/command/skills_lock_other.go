//go:build !darwin && !linux

package command

import (
	"context"
	"errors"
	"os"
)

func acquireSkillsLock(_ context.Context, _ *os.Root) (*os.File, error) {
	return nil, errors.New("skills: safe store locking is unsupported on this platform")
}
