package daemonctl

import (
	"errors"
	"os"
	"os/exec"
)

type osLauncher struct{}

func (osLauncher) Start(path string, args []string, opts launchOptions) (process, error) {
	cmd := exec.Command(path, args...) // #nosec G204 -- binary is resolved from a fixed name, an explicit override, or the CLI's own directory.
	cmd.Dir = opts.Dir
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	if opts.Detach {
		configureDetached(cmd)
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &osProcess{cmd: cmd}, nil
}

func (osLauncher) Find(pid int) (process, error) {
	if pid <= 0 {
		return nil, ErrProcessNotFound
	}
	found, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}
	return foundProcess{process: found}, nil
}

type osProcess struct {
	cmd *exec.Cmd
}

func (p *osProcess) PID() int {
	return p.cmd.Process.Pid
}

func (p *osProcess) Signal(signal os.Signal) error {
	return p.cmd.Process.Signal(signal)
}

func (p *osProcess) Kill() error {
	return p.cmd.Process.Kill()
}

func (p *osProcess) Wait() error {
	return p.cmd.Wait()
}

type foundProcess struct {
	process *os.Process
}

func (p foundProcess) PID() int {
	return p.process.Pid
}

func (p foundProcess) Signal(signal os.Signal) error {
	return p.process.Signal(signal)
}

func (p foundProcess) Kill() error {
	err := p.process.Kill()
	_ = p.process.Release()
	return err
}

func (foundProcess) Wait() error {
	return errors.New("cannot wait for a process found by PID")
}
