//go:build !unix

package sshxtest

import "os/exec"

// newProcessGroup does nothing where there are no process groups.
func newProcessGroup(*exec.Cmd) {}

// killProcessGroup does nothing where there are no process groups.
func killProcessGroup(int) {}
