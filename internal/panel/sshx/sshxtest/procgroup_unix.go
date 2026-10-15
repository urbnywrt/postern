//go:build unix

package sshxtest

import (
	"os/exec"
	"syscall"
)

// newProcessGroup makes cmd start in a process group of its own, so that what
// it leaves behind can be ended with it.
func newProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup ends every process of the group that pid leads.
func killProcessGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
