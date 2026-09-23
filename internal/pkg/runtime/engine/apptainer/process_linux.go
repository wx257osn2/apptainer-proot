// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2018-2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package apptainer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/apptainer/apptainer/internal/pkg/instance"
	"github.com/apptainer/apptainer/internal/pkg/plugin"
	"github.com/apptainer/apptainer/internal/pkg/runtime/engine/apptainer/actionscript"
	"github.com/apptainer/apptainer/internal/pkg/security"
	"github.com/apptainer/apptainer/internal/pkg/util/env"
	"github.com/apptainer/apptainer/internal/pkg/util/user"
	apptainercallback "github.com/apptainer/apptainer/pkg/plugin/callback/runtime/engine/apptainer"
	"github.com/apptainer/apptainer/pkg/sylog"
	"github.com/apptainer/apptainer/pkg/util/fs/lock"
	"github.com/apptainer/apptainer/pkg/util/rlimit"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// StartProcess is called during stage2 after RPC server finished
// environment preparation. This is the container process itself.
//
// No additional privileges can be gained during this call (unless container
// is executed as root intentionally) as starter will set uid/euid/suid
// to the targetUID (PrepareConfig will set it by calling starter.Config.SetTargetUID).
//
//nolint:maintidx
func (e *EngineOperations) StartProcess(masterConnFd int) error {
	isInstance := e.EngineConfig.GetInstance() && !e.EngineConfig.GetShareNSMode()
	bootInstance := isInstance && e.EngineConfig.GetBootInstance()
	shimProcess := false

	// close the opened fd inside container, preventing leak
	if fd := e.EngineConfig.GetShareNSFd(); fd != -1 && e.EngineConfig.GetShareNSMode() {
		shimProcess = true
		sylog.Debugf("Close --sharens fd lock, fd: %d", fd)
		_ = unix.Close(fd)
	}

	// Manage all signals.
	// Queue them until they're ready to be handled below.
	// Use a channel size of two here, since we may receive SIGURG, which is
	// used for non-cooperative goroutine preemption starting with Go 1.14.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals)

	if err := e.runFuseDrivers(true, -1); err != nil {
		return err
	}

	if err := actionscript.SetWorkingDirectory(e.EngineConfig); err != nil {
		return err
	}

	actionscript.ReplaceTerminal(e.EngineConfig)

	if e.EngineConfig.OciConfig.Linux != nil {
		namespaces := e.EngineConfig.OciConfig.Linux.Namespaces
		for _, ns := range namespaces {
			if ns.Type == specs.PIDNamespace {
				if !e.EngineConfig.GetNoInit() {
					shimProcess = true
				}
				break
			}
		}
	}

	for _, img := range e.EngineConfig.GetImageList() {
		// bad file descriptor error is ignored because
		// the file descriptor has been previously closed
		// in this loop, happens when a SIF image contains
		// overlay partition in it as each SIF overlay
		// partition is considered as a single image with
		// different offset/size but pointing to the same
		// opened image file descriptor
		if err := syscall.Close(int(img.Fd)); err != nil && err != syscall.EBADF {
			return fmt.Errorf("failed to close file descriptor for %s: %s", img.Path, err)
		}
	}

	for _, fd := range e.EngineConfig.GetOpenFd() {
		if err := syscall.Close(fd); err != nil {
			return fmt.Errorf("aborting failed to close file descriptor: %s", err)
		}
	}

	// restore the stack size limit for setuid workflow
	for _, limit := range e.EngineConfig.OciConfig.Process.Rlimits {
		if limit.Type == "RLIMIT_STACK" {
			if err := rlimit.Set(limit.Type, limit.Soft, limit.Hard); err != nil {
				return fmt.Errorf("while restoring stack size limit: %s", err)
			}
			break
		}
	}

	if err := security.Configure(&e.EngineConfig.OciConfig.Spec); err != nil {
		return fmt.Errorf("failed to apply security configuration: %s", err)
	}

	actionscript.RestoreUmask(e.EngineConfig)

	if (!isInstance && !shimProcess) || bootInstance || e.EngineConfig.GetInstanceJoin() {
		args := e.EngineConfig.OciConfig.Process.Args
		env := e.EngineConfig.OciConfig.Process.Env

		if !bootInstance {
			var err error

			args, env, err = actionscript.Run(e.EngineConfig)
			if err != nil {
				return err
			} else if len(args) == 0 {
				// nothing to execute and no error was reported
				return nil
			}
		}

		return e.execProcess(args, env)
	}

	errChan := make(chan error, 1)
	statusChan := make(chan syscall.WaitStatus, 1)
	cmdPid := -2

	args, env, err := actionscript.Run(e.EngineConfig)
	if err != nil {
		return err
	} else if len(args) > 0 {
	cmdexec:
		// Spawn and wait container process, signal handler
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: isInstance,
		}
		if err := cmd.Start(); err != nil {
			if e, ok := err.(*os.PathError); ok {
				if e.Err.(syscall.Errno) == syscall.ENOEXEC && args[0] != actionscript.DefaultShell {
					args = append([]string{actionscript.DefaultShell}, args...)
					goto cmdexec
				}
			}
			return fmt.Errorf("exec %s failed: %s", args[0], err)
		}
		cmdPid = cmd.Process.Pid

		go func() {
			errChan <- cmd.Wait()
		}()
	}

	// Modify argv argument and program name shown in /proc/self/comm
	name := "appinit"

	argv0 := unsafe.Slice(unsafe.StringData(os.Args[0]), len(os.Args[0]))
	progname := make([]byte, len(os.Args[0]))

	if len(name) > len(progname) {
		return fmt.Errorf("program name too short")
	}

	copy(progname, name)

	// Set name by overwriting argv[0]
	copy(argv0, progname)

	// Set name by PR_SET_NAME (only affects PR_GET_NAME)
	ptr := unsafe.Pointer(&progname[0])
	if _, _, err := syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_SET_NAME, uintptr(ptr), 0); err != 0 {
		return syscall.Errno(err)
	}

	syscall.Close(masterConnFd)

	for {
		select {
		case s := <-signals:
			sylog.Debugf("Received signal %s", s.String())
			switch s {
			case syscall.SIGCHLD:
				for {
					var status syscall.WaitStatus

					wpid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
					if wpid <= 0 || err != nil {
						// We break the loop since an error occurred
						break
					}

					if wpid == cmdPid {
						e.stopFuseDrivers()
						statusChan <- status
					}
				}
			case syscall.SIGURG:
				// Ignore SIGURG, which is used for non-cooperative goroutine
				// preemption starting with Go 1.14. For more information, see
				// https://github.com/golang/go/issues/24543.
				break
			default:
				signal := s.(syscall.Signal)
				// EPERM and EINVAL are deliberately ignored because they can't be
				// returned in this context, this process is PID 1, so it has the
				// permissions to send signals to its childs and EINVAL would
				// mean to update the Go runtime or the kernel to something more
				// stable :)
				if (isInstance || e.EngineConfig.GetShareNSMode()) && cmdPid > 0 {
					if err := syscall.Kill(-cmdPid, signal); err == syscall.ESRCH {
						sylog.Debugf("No child process, exiting ...")
						os.Exit(128 + int(signal))
					}
				} else if e.EngineConfig.GetSignalPropagation() && cmdPid > 0 {
					if err := syscall.Kill(cmdPid, signal); err == syscall.ESRCH {
						sylog.Debugf("No child process, exiting ...")
						os.Exit(128 + int(signal))
					}
				}
			}
		case err := <-errChan:
			if e, ok := err.(*exec.ExitError); ok {
				status, ok := e.Sys().(syscall.WaitStatus)
				if !ok {
					return fmt.Errorf("command exit with error: %s", err)
				}
				statusChan <- status
			} else if e, ok := err.(*os.SyscallError); ok {
				// handle possible race with Wait4 call above by ignoring ECHILD
				// error because child process was already caught
				if e.Err.(syscall.Errno) != syscall.ECHILD {
					sylog.Fatalf("error while waiting container process: %s", e.Error())
				}
			}
			if !isInstance {
				if len(statusChan) > 0 {
					status := <-statusChan
					if status.Signaled() {
						os.Exit(128 + int(status.Signal()))
					}
					os.Exit(status.ExitStatus())
				} else if err == nil {
					os.Exit(0)
				}
				sylog.Fatalf("command exited with unknown error: %s", err)
			}
		}
	}
}

// PostStartProcess is called from master after successful
// execution of the container process. It will write instance
// state/config files (if any).
//
// Additional privileges may be gained when running
// in suid flow. However, when a user namespace is requested and it is not
// a hybrid workflow (e.g. fakeroot), then there is no privileged saved uid
// and thus no additional privileges can be gained.
//
// Here, however, apptainer engine does not escalate privileges.
func (e *EngineOperations) PostStartProcess(_ context.Context, pid int) error {
	sylog.Debugf("Post start process")

	callbackType := (apptainercallback.PostStartProcess)(nil)
	callbacks, err := plugin.LoadCallbacks(callbackType)
	if err != nil {
		return fmt.Errorf("while loading plugins callbacks '%T': %s", callbackType, err)
	}
	for _, cb := range callbacks {
		if err := cb.(apptainercallback.PostStartProcess)(e.CommonConfig, pid); err != nil {
			return err
		}
	}

	if e.EngineConfig.GetInstance() {
		os.Setenv("APPTAINER_CONFIGDIR", e.EngineConfig.GetConfigDir())

		name := e.CommonConfig.ContainerID

		if err := os.Chdir("/"); err != nil {
			return fmt.Errorf("failed to change directory to /: %s", err)
		}

		file, err := instance.Add(name, instance.AppSubDir)
		if err != nil {
			return err
		}

		// add sharens flag
		file.ShareNSMode = e.EngineConfig.GetShareNSMode()

		pw, err := user.CurrentOriginal()
		if err != nil {
			return err
		}

		logErrPath, logOutPath, err := instance.GetLogFilePaths(name, instance.LogSubDir)
		if err != nil {
			return fmt.Errorf("could not find log paths: %s", err)
		}

		file.User = pw.Name
		file.Pid = pid
		file.PPid = os.Getpid()
		file.Image = e.EngineConfig.GetImage()
		file.LogErrPath = logErrPath
		file.LogOutPath = logOutPath
		file.Checkpoint = e.EngineConfig.GetDMTCPConfig().Checkpoint

		ip, err := e.getIP()
		if err != nil {
			sylog.Warningf("Could not get ip for %s: %s", pw.Name, err)
		}
		file.IP = ip

		// by default we add all namespaces except the user namespace which
		// is added conditionally. This delegates checks to the C starter code
		// which will determine if a namespace needs to be joined by
		// comparing namespace inodes
		path := fmt.Sprintf("/proc/%d/ns", pid)
		namespaces := []struct {
			nstype string
			ns     specs.LinuxNamespaceType
		}{
			{"pid", specs.PIDNamespace},
			{"uts", specs.UTSNamespace},
			{"ipc", specs.IPCNamespace},
			{"mnt", specs.MountNamespace},
			{"cgroup", specs.CgroupNamespace},
			{"net", specs.NetworkNamespace},
		}
		for _, n := range namespaces {
			nspath := filepath.Join(path, n.nstype)
			e.EngineConfig.OciConfig.AddOrReplaceLinuxNamespace(n.ns, nspath)
		}
		for _, ns := range e.EngineConfig.OciConfig.Linux.Namespaces {
			if ns.Type == specs.UserNamespace {
				nspath := filepath.Join(path, "user")
				e.EngineConfig.OciConfig.AddOrReplaceLinuxNamespace(specs.UserNamespace, nspath)
				file.UserNs = true
				break
			}
		}

		// If we are using cgroups with this instance then mark that in the instance config.
		// We don't store the path, as we will get the cgroup manager by Pid.
		if e.EngineConfig.GetCgroupsJSON() != "" {
			file.Cgroup = true
		}

		// grab configuration to store in instance file
		file.Config, err = json.Marshal(e.CommonConfig)
		if err != nil {
			return err
		}

		err = file.Update()
		if err != nil {
			return err
		}

		if !e.EngineConfig.GetShareNSMode() {
			// send SIGUSR1 to the parent process in order to tell it
			// to detach container process and run as instance.
			// Sleep a bit in case child would exit
			time.Sleep(100 * time.Millisecond)
			if err := syscall.Kill(os.Getppid(), syscall.SIGUSR1); err != nil {
				return err
			}
		} else if fd := e.EngineConfig.GetShareNSFd(); fd != -1 {
			// here first process in the --sharens mode starts properly
			// as there are chances that the lock file will not be removed properly
			// and it'll be difficult to distinguish the successful startup and false one
			// here we will write one byte data into the lock file to indicate that first process
			// starts correctly.
			if _, err := unix.Pwrite(fd, []byte{1}, io.SeekStart); err != nil {
				return err
			}

			br := lock.NewByteRange(fd, 0, 0)
			if err := br.Unlock(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *EngineOperations) setPathEnv() {
	env := e.EngineConfig.OciConfig.Process.Env
	for _, keyval := range env {
		if strings.HasPrefix(keyval, "PATH=") {
			os.Setenv("PATH", keyval[5:])
			break
		}
	}
}

// runFuseDrivers execute FUSE drivers and returns the list of FUSE process ID.
func (e *EngineOperations) runFuseDrivers(fromContainer bool, usernsFd int) error {
	// set PATH for the command
	oldpath := os.Getenv("PATH")
	defer func() {
		os.Setenv("PATH", oldpath)
	}()

	if fromContainer {
		e.setPathEnv()
	} else {
		os.Setenv("PATH", env.DefaultPath)
	}

	for _, fd := range e.EngineConfig.GetUnixSocketPair() {
		if fd >= 0 {
			unix.Close(fd)
		}
	}

	var usernsFh *os.File

	if usernsFd >= 0 {
		usernsFh = os.NewFile(uintptr(usernsFd), "/proc/self/ns/user")
		if usernsFh == nil {
			// this should never happen
			return errors.New("cannot map /proc/self/ns/user file descriptor to a file handle")
		}
		defer usernsFh.Close()
	}

	fuseMounts := e.EngineConfig.GetFuseMount()
	for i := range fuseMounts {
		if fromContainer != fuseMounts[i].FromContainer {
			syscall.Close(fuseMounts[i].Fd)
			continue
		}

		mnt := fuseMounts[i].MountPoint
		program := fuseMounts[i].Program
		fd := fuseMounts[i].Fd

		sylog.Debugf("Running FUSE driver for %s as %v, fd %d", mnt, program, fd)

		fh := os.NewFile(uintptr(fd), "/dev/fuse")
		if fh == nil {
			// this should never happen
			return errors.New("cannot map /dev/fuse file descriptor to a file handle")
		}
		// the master process does not need this file descriptor after
		// running the program, make sure it gets closed; ignore any
		// errors that happen here
		defer fh.Close()

		// as we pass file handle as first element in ExtraFiles
		// the fuse file descriptor becomes 3 for the FUSE program
		args := append(program, "/dev/fd/3")

		// add -f to run FUSE in foreground mode
		if !fuseMounts[i].Daemon {
			args = append(args, "-f")
		}

		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout

		// Add the /dev/fuse file descriptor to the list of file
		// descriptors to be passed to the new process.
		// The Go library will set things up so that stdin, stdout
		// and stderr are 0, 1, and 2, so the first element of
		// ExtraFiles gets 3
		cmd.ExtraFiles = make([]*os.File, 1)
		cmd.ExtraFiles[0] = fh

		// Add /proc/<container_pid>/ns/user file descriptor for nsenter
		// so it could join the container user namespace by using /dev/fd/4
		if usernsFh != nil {
			cmd.ExtraFiles = append(cmd.ExtraFiles, usernsFh)
		}

		if fuseMounts[i].Daemon {
			if err := cmd.Run(); err != nil {
				cmdline := strings.Join(args, " ")
				return fmt.Errorf("could not start program %s: %s", cmdline, err)
			}
		} else {
			if err := cmd.Start(); err != nil {
				cmdline := strings.Join(args, " ")
				return fmt.Errorf("could not start program %s: %s", cmdline, err)
			}
			fuseMounts[i].Cmd = cmd
		}
	}

	return nil
}

// stopFuseDrivers notifies FUSE drivers running in foreground mode
// with a SIGTERM signal.
func (e *EngineOperations) stopFuseDrivers() {
	for _, fuseMount := range e.EngineConfig.GetFuseMount() {
		if fuseMount.Cmd != nil {
			cmd := fuseMount.Cmd
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				sylog.Warningf("Can not send SIGTERM to FUSE process: %s", err)
				continue
			}
			mnt := fuseMount.MountPoint
			_, err := cmd.Process.Wait()
			if err != nil {
				sylog.Warningf("FUSE process for mount point %s terminated with error: %s", mnt, err)
			} else {
				sylog.Debugf("FUSE process for mount point %s terminated", mnt)
			}
		}
	}
}

func (e *EngineOperations) getIP() (string, error) {
	if networkSetup == nil {
		return "", nil
	}

	net := strings.Split(e.EngineConfig.GetNetwork(), ",")

	ip, err := networkSetup.GetNetworkIP(net[0], "4")
	if err == nil {
		return ip.String(), nil
	}
	sylog.Warningf("Could not get ipv4 %s", err)

	ip, err = networkSetup.GetNetworkIP(net[0], "6")
	if err == nil {
		return ip.String(), nil
	}
	sylog.Warningf("Could not get ipv6 %s", err)

	return "", errors.New("could not get ip")
}

func (e *EngineOperations) execProcess(args, env []string) error {
	return actionscript.Exec(args, env, e.EngineConfig.GetShell())
}
