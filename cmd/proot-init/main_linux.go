// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Command proot-init is the first process started under proot inside the
// container. It reads the engine configuration from file descriptor 3,
// evaluates the action script and runs the container process. It reports
// the PID then the wait status of the container process on file descriptor
// 4, because the proot exit status reflects any failing process.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/apptainer/apptainer/internal/pkg/runtime/engine/apptainer/actionscript"
	apptainerConfig "github.com/apptainer/apptainer/pkg/runtime/engine/apptainer/config"
	"github.com/apptainer/apptainer/pkg/sylog"
)

const (
	configFd = 3
	statusFd = 4
)

func init() {
	// proot mishandles process creation from a thread other than the
	// thread group leader, so main must keep running on the initial thread.
	runtime.LockOSThread()
}

// start starts the container process, running scripts without an
// interpreter line with the default shell.
func start(args, env []string, shell string) (*exec.Cmd, error) {
	cmd := exec.Command(args[0])
	cmd.Args = args
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if errors.Is(err, syscall.ENOEXEC) && args[0] != actionscript.DefaultShell {
		return start(append([]string{actionscript.DefaultShell}, args...), env, shell)
	} else if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			return nil, actionscript.ExecError(errno, args, shell)
		}
		return nil, err
	}
	return cmd, nil
}

func main() {
	engineConfig := apptainerConfig.NewConfig()

	configFile := os.NewFile(configFd, "engine-config")
	if err := json.NewDecoder(configFile).Decode(engineConfig); err != nil {
		sylog.Fatalf("While reading engine configuration: %s", err)
	}
	configFile.Close()
	syscall.CloseOnExec(statusFd)
	statusFile := os.NewFile(statusFd, "status")

	if err := actionscript.SetWorkingDirectory(engineConfig); err != nil {
		sylog.Fatalf("%s", err)
	}
	actionscript.ReplaceTerminal(engineConfig)
	actionscript.RestoreUmask(engineConfig)

	args, env, err := actionscript.Run(engineConfig)
	if err != nil {
		sylog.Fatalf("%s", err)
	} else if len(args) == 0 {
		return
	}

	// Signals from the terminal also reach the container process, the
	// others are forwarded to it by apptainer. They are caught, and
	// dropped as the channel is never read, rather than ignored so the
	// container process keeps default dispositions.
	signal.Notify(make(chan os.Signal, 1))

	cmd, err := start(args, env, engineConfig.GetShell())
	if err != nil {
		sylog.Fatalf("%s", err)
	}
	if _, err := fmt.Fprintf(statusFile, "%d\n", cmd.Process.Pid); err != nil {
		sylog.Warningf("While reporting container process PID: %s", err)
	}

	err = cmd.Wait()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		sylog.Fatalf("While waiting container process: %s", err)
	}
	status := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if _, err := fmt.Fprintf(statusFile, "%d\n", uint32(status)); err != nil {
		sylog.Warningf("While reporting container process status: %s", err)
	}
	statusFile.Close()

	if status.Signaled() {
		os.Exit(128 + int(status.Signal()))
	}
	os.Exit(status.ExitStatus())
}
