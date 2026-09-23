// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// Copyright (c) 2018-2022, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Package actionscript evaluates the container action script and executes
// the resulting container process. It does not depend on cgo so it can be
// linked into static helpers running inside the container.
package actionscript

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/apptainer/apptainer/internal/pkg/checkpoint/dmtcp"
	"github.com/apptainer/apptainer/internal/pkg/fakeroot"
	"github.com/apptainer/apptainer/internal/pkg/util/env"
	"github.com/apptainer/apptainer/internal/pkg/util/fs/files"
	"github.com/apptainer/apptainer/internal/pkg/util/machine"
	"github.com/apptainer/apptainer/internal/pkg/util/shell"
	"github.com/apptainer/apptainer/internal/pkg/util/shell/interpreter"
	apptainerConfig "github.com/apptainer/apptainer/pkg/runtime/engine/apptainer/config"
	"github.com/apptainer/apptainer/pkg/sylog"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"mvdan.cc/sh/v3/interp"
)

// DefaultShell is the shell used to run scripts without an interpreter line.
const DefaultShell = "/bin/sh"

// ExecError returns an error explaining why the container process args
// failed to execute with err.
func ExecError(err error, args []string, shell string) error {
	// We know the shell exists at this point, so let's inspect its architecture
	if shell == "" {
		shell = DefaultShell
	}
	elfArch, elfErr := machine.ArchFromElf(shell)
	if elfErr != nil && elfErr != machine.ErrUnknownArch {
		return fmt.Errorf("failed to open %s for inspection: %s", shell, elfErr)
	} else if elfErr == machine.ErrUnknownArch {
		elfArch = "unknown architecture"
	}
	if elfArch != runtime.GOARCH {
		return fmt.Errorf("image targets '%s', cannot run on '%s'", elfArch, runtime.GOARCH)
	}
	// Assume a missing shared library on ENOENT
	if err == syscall.ENOENT {
		return fmt.Errorf("exec %s failed: a shared library is likely missing in the image", args[0])
	}
	// Return the raw error as a last resort
	return fmt.Errorf("exec %s failed: %s", args[0], err)
}

// SetWorkingDirectory changes to the container process working directory,
// falling back to the home directory and then to /.
func SetWorkingDirectory(engineConfig *apptainerConfig.EngineConfig) error {
	_, customCwd := engineConfig.OciConfig.Annotations["CustomCwd"]

	if err := os.Chdir(engineConfig.OciConfig.Process.Cwd); err != nil {
		if customCwd {
			return fmt.Errorf("failed to set working directory: %s", err)
		}
		if cerr := os.Chdir(engineConfig.GetHomeDest()); cerr != nil {
			sylog.Warningf("Error changing the container working directory. Using '/' instead: %s", cerr)
			os.Chdir("/")
		} else {
			sylog.Warningf("Error changing the container working directory. Using '%s' instead: %s", engineConfig.GetHomeDest(), err)
		}
	}
	return nil
}

// ReplaceTerminal replaces terminal file descriptors by /dev/console when
// the container uses a minimal /dev.
func ReplaceTerminal(engineConfig *apptainerConfig.EngineConfig) {
	if engineConfig.File.MountDev == "minimal" || engineConfig.GetContain() {
		// If on a terminal, reopen /dev/console so /proc/self/fd/[0-2
		//   will point to /dev/console.  This is needed so that tty and
		//   ttyname() on el6 will return the correct answer.  Newer
		//   ttyname() functions might work because they will search
		//   /dev if the value of /proc/self/fd/X doesn't exist, but
		//   they won't work if another /dev/pts/X is allocated in its
		//   place.  Also, programs that don't use ttyname() and instead
		//   directly do readlink() on /proc/self/fd/X need this.
		for fd := 0; fd <= 2; fd++ {
			if !term.IsTerminal(fd) {
				continue
			}
			consfile, err := os.OpenFile("/dev/console", os.O_RDWR, 0o600)
			if err != nil {
				sylog.Debugf("Could not open minimal /dev/console, skipping replacing tty descriptors")
				break
			}
			sylog.Debugf("Replacing tty descriptors with /dev/console")
			consfd := int(consfile.Fd())
			for ; fd <= 2; fd++ {
				if !term.IsTerminal(fd) {
					continue
				}
				syscall.Close(fd)
				syscall.Dup3(consfd, fd, 0)
			}
			consfile.Close()
			break
		}
	}
}

// RestoreUmask sets the umask saved from the calling environment, if
// necessary.
// https://github.com/apptainer/singularity/issues/5214
func RestoreUmask(engineConfig *apptainerConfig.EngineConfig) {
	if engineConfig.GetRestoreUmask() {
		sylog.Debugf("Setting umask in container to %04o", engineConfig.GetUmask())
		_ = syscall.Umask(engineConfig.GetUmask())
	}
}

// Exec replaces the current process with the container process, falling
// back to DefaultShell for scripts without an interpreter line.
func Exec(args, env []string, shell string) error {
	err := syscall.Exec(args[0], args, env)
	if err == nil {
		return nil
	}
	if err == syscall.ENOEXEC && args[0] != DefaultShell {
		args = append([]string{DefaultShell}, args...)
		return Exec(args, env, shell)
	}
	return ExecError(err, args, shell)
}

// bufferCloser wraps a bytes.Buffer with a Close method
// required by the open handler of the shell interpreter.
type bufferCloser struct {
	bytes.Buffer
}

func (b *bufferCloser) Close() error {
	b.Reset()
	return nil
}

// Register a virtual file /.singularity.d/env/inject-apptainer-env.sh sourced
// after /.singularity.d/env/99-base.sh or /environment.
// This handler turns all SINGUALRITYENV_KEY=VAL defined variables into their form:
// export KEY=VAL. It can be sourced only once otherwise it returns an empty content.
// If noEval is true then exports are single quoted so their content is not evaluated
// when the script is sourced (OCI compatible behavior).
// If noEval is false then exports are double quoted, and their content is evaluated,
// consuming one level of shell escaping and performing any unescaped var substitution,
// subshell execution etc (Apptainer historic behavior).
func injectEnvHandler(senv map[string]string, noEval bool) interpreter.OpenHandler {
	var once sync.Once

	return func(_ string, _ int, _ os.FileMode) (io.ReadWriteCloser, error) {
		b := new(bufferCloser)

		once.Do(func() {
			defaultPathSnippet := `
			if ! test -v PATH; then
				export PATH=%q
			fi
			`
			fmt.Fprintf(b, defaultPathSnippet, env.DefaultPath)

			snippet := `
			if test -v %[1]s; then
				sylog debug "Overriding %[1]s environment variable"
			fi
			export %[1]s=%[2]s
			`
			for key, value := range senv {
				if key == "UID" || key == "GID" {
					continue
				}
				if key == "LD_LIBRARY_PATH" && value != "" {
					value = value + ":/.singularity.d/libs"
				}
				if noEval {
					// No evaluation when the export is sourced
					value = "'" + shell.EscapeSingleQuotes(value) + "'"
				} else {
					// Shell evaluation when the export is sourced
					value = "\"" + shell.EscapeDoubleQuotes(value) + "\""
				}
				fmt.Fprintf(b, snippet, key, value)
			}
		})

		return b, nil
	}
}

func runtimeVarsHandler() interpreter.OpenHandler {
	var once sync.Once

	return func(_ string, _ int, _ os.FileMode) (io.ReadWriteCloser, error) {
		b := new(bufferCloser)

		once.Do(func() {
			b.WriteString(files.RuntimeVars)
		})

		return b, nil
	}
}

// sylogBuiltin allows to use sylog logger from shell script.
func sylogBuiltin(_ context.Context, argv []string) error {
	if len(argv) < 2 {
		return fmt.Errorf("sylog builtin requires two arguments")
	}
	switch argv[0] {
	case "info":
		sylog.Infof("%s", argv[1])
	case "error":
		sylog.Errorf("%s", argv[1])
	case "verbose":
		sylog.Verbosef("%s", argv[1])
	case "debug":
		sylog.Debugf("%s", argv[1])
	case "warning":
		sylog.Warningf("%s", argv[1])
	}
	return nil
}

// getAllEnvBuiltin display all exported variables in the form KEY=VALUE.
func getAllEnvBuiltin() interpreter.ShellBuiltin {
	return func(ctx context.Context, _ []string) error {
		hc := interp.HandlerCtx(ctx)

		keyRe := regexp.MustCompile(`^[a-zA-Z_]+[a-zA-Z0-9_]*$`)

		for _, env := range interpreter.GetEnv(hc) {
			// Exclude environment vars that contain invalid characters
			// in their KEY - e.g. bash functions in the environment
			// like "BASH_FUNC_module%%"
			key := strings.SplitN(env, "=", 2)[0]
			if !keyRe.MatchString(key) {
				sylog.Debugf("Not exporting %q to container environment: invalid key", key)
				continue
			}
			// Because we are using IFS=\n we need to escape newlines here and
			// unescape them in the action script when we export the var again.
			//
			// This is imperfect - it is not possible to represent a string
			// containing a literal '\u000A' (unicode escaped newline) in it.
			//
			// Full escaping / unescaping requires iterative parsing of the
			// string in the action script. This is too awkward and slow in
			// shell code. If we can use `printf -v VAR "%b" ...` from mvdan.cc/sh
			// in future, we may be able to revisit this.
			env := strings.ReplaceAll(env, "\n", "\\u000A")
			fmt.Fprintf(hc.Stdout, "%s\n", env)
		}
		return nil
	}
}

// fixPathBuiltin takes the current path value to fix it by injecting
// missing default path and returns value on shell interpreter output.
func fixPathBuiltin(ctx context.Context, _ []string) error {
	hc := interp.HandlerCtx(ctx)

	currentPath := filepath.SplitList(hc.Env.Get("PATH").String())
	finalPath := currentPath

	for _, d := range filepath.SplitList(env.DefaultPath) {
		found := false
		for _, p := range currentPath {
			if d == p {
				found = true
				continue
			}
		}
		if !found {
			finalPath = append(finalPath, d)
		}
	}

	listSep := string(os.PathListSeparator)
	fmt.Fprintf(hc.Stdout, "%s\n", strings.Join(finalPath, listSep))
	return nil
}

// hashBuiltin is a noop function for hash bash builtin, since we don't
// store resolved path in a hash table, there is nothing to do.
func hashBuiltin(_ context.Context, _ []string) error {
	return nil
}

func umaskBuiltin(ctx context.Context, argv []string) error {
	hc := interp.HandlerCtx(ctx)

	if len(argv) == 0 {
		old := unix.Umask(0)
		unix.Umask(old)
		fmt.Fprintf(hc.Stdout, "%#.4o\n", old)
	} else {
		umask, err := strconv.ParseUint(argv[0], 8, 16)
		if err != nil {
			return fmt.Errorf("umask: %s: invalid octal number: %s", argv[0], err)
		}
		unix.Umask(int(umask))
	}

	return nil
}

func getEnvVal(env []string, envname string) string {
	envname += "="
	for _, keyval := range env {
		if strings.HasPrefix(keyval, envname) {
			return keyval[len(envname):]
		}
	}
	return ""
}

// Run interprets and executes the action script within
// an embedded shell interpreter.
func Run(engineConfig *apptainerConfig.EngineConfig) ([]string, []string, error) {
	args := engineConfig.OciConfig.Process.Args
	penv := append(engineConfig.OciConfig.Process.Env, "APPTAINER_COMMAND="+filepath.Base(args[0]))
	var execCtx context.Context
	if timeoutVal := engineConfig.GetRunscriptTimeout(); timeoutVal != "" {
		timeoutDur, err := time.ParseDuration(timeoutVal)
		if err != nil {
			return nil, nil, err
		}
		timeoutCtx, cancel := context.WithTimeout(context.Background(), timeoutDur)
		defer cancel()
		execCtx = context.WithValue(timeoutCtx, interpreter.TimeoutKey, timeoutDur)
	} else {
		timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		execCtx = context.WithValue(timeoutCtx, interpreter.TimeoutKey, time.Minute)
	}

	b := bytes.NewBufferString(files.ActionScript)

	shell, err := interpreter.New(b, args[0], args[1:], penv)
	if err != nil {
		return nil, nil, err
	}

	execBuiltin := func(ctx context.Context, argv []string) error {
		dmtcpConfig := engineConfig.GetDMTCPConfig()
		if dmtcpConfig.Enabled {
			argv = dmtcp.InjectArgs(dmtcpConfig, argv)
			sylog.Debugf("Injected DMTCP args %+q", argv)
		}

		cmd, err := shell.LookPath(ctx, argv[0])
		if err != nil {
			return err
		}
		penv = interpreter.GetEnv(interp.HandlerCtx(ctx))
		argv[0] = cmd
		args = argv
		return nil
	}

	// inject APPTAINERENV_ defined variables
	senv := engineConfig.GetApptainerEnv()
	shell.RegisterOpenHandler("/.inject-apptainer-env.sh", injectEnvHandler(senv, engineConfig.GetNoEval()))

	shell.RegisterOpenHandler("/.singularity.d/env/99-runtimevars.sh", runtimeVarsHandler())

	// register few builtin
	shell.RegisterShellBuiltin("getallenv", getAllEnvBuiltin())
	shell.RegisterShellBuiltin("sylog", sylogBuiltin)
	shell.RegisterShellBuiltin("fixpath", fixPathBuiltin)
	shell.RegisterShellBuiltin("hash", hashBuiltin)
	shell.RegisterShellBuiltin("umask_builtin", umaskBuiltin)

	// exec builtin won't execute the command but instead
	// it returns arguments and environment variables and
	// let the responsibility to the caller of this
	// function to execute the command
	shell.RegisterShellBuiltin("exec", execBuiltin)

	err = shell.Run(execCtx)
	if err != nil {
		if shell.Status() != 0 {
			os.Exit(int(shell.Status()))
		}
		return nil, nil, err
	}

	if len(args) > 0 && args[0] == "/.singularity.d/runscript" {
		b, err := getDockerRunscript(args[0])
		if err != nil {
			return nil, nil, err
		} else if b != nil {
			interp, err := interpreter.New(b, args[0], args[1:], penv)
			if err != nil {
				return nil, nil, err
			}
			interp.RegisterShellBuiltin("exec", execBuiltin)
			err = interp.Run(execCtx)
			if err != nil {
				if interp.Status() != 0 {
					os.Exit(int(interp.Status()))
				}
				return nil, nil, err
			}
		}
	}

	fakeargs := fakeroot.GetFakeArgs()
	fakerootPath := fakeargs[0]
	_, err = os.Stat(fakerootPath)
	if err == nil && getEnvVal(penv, "FAKEROOTKEY") == "" {
		// fakeroot command exists but we're not running nested
		sylog.Verbosef("Running command with %v", filepath.Base(fakerootPath))
		args = append(fakeargs, args...)

		penv = fakeroot.GetFakeEnviron(penv, false)

		if engineConfig.GetFakerootPath() == "" {
			// Must be joining an instance, so also set BIND
			//  variables for nesting
			fakebinds, _ := fakeroot.GetFakeBinds(fakerootPath)
			bindval := strings.Join(fakebinds, ",")
			for _, pfx := range env.ApptainerPrefixes {
				bindvar := pfx + "BIND="
				for idx, keyval := range penv {
					if !strings.HasPrefix(keyval, bindvar) {
						continue
					}
					val := keyval[len(bindvar):]
					if val != "" {
						val += ","
					}
					val += bindval
					penv[idx] = bindvar + val
					break
				}
			}
		}
	}

	return args, penv, nil
}

// getDockerRunscript returns the content as a reader of
// the default runscript set for docker images if any.
func getDockerRunscript(path string) (io.Reader, error) {
	r, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("while reading %s: %s", path, err)
	}
	var b bytes.Buffer

	if _, err := b.Write(r); err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(&b)

	for scanner.Scan() {
		if scanner.Text() == "eval \"set ${SINGULARITY_OCI_RUN}\"" {
			b.Reset()
			if _, err := b.Write(r); err != nil {
				return nil, err
			}
			return &b, nil
		}
	}

	return nil, nil
}
