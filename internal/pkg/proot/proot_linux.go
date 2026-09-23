// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Package proot provides the checks deciding whether containers can and
// must run under proot instead of in a user namespace.
package proot

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/apptainer/apptainer/internal/pkg/buildcfg"
	"github.com/apptainer/apptainer/internal/pkg/util/bin"
	"github.com/apptainer/apptainer/pkg/sylog"
	"github.com/apptainer/apptainer/pkg/util/apptainerconf"
	"github.com/apptainer/apptainer/pkg/util/namespaces"
)

// Values of the 'use proot' configuration directive.
const (
	ModeAuto = "auto"
	ModeYes  = "yes"
	ModeNo   = "no"
)

const (
	sysctlDir     = "/proc/sys"
	apparmorDir   = "/etc/apparmor.d"
	apparmorFlags = "/sys/module/apparmor/parameters/enabled"
)

// HasWorkingPtrace returns true if the ptrace() system call is usable.
// proot relies on ptrace, which can be unavailable because of a seccomp
// filter, an AppArmor/Yama restriction, or because Apptainer itself is
// running inside another container without the CAP_SYS_PTRACE capability.
func HasWorkingPtrace() bool {
	// Use the currently running executable as the traced child: since
	// PTRACE_TRACEME causes the child to stop with SIGTRAP right after
	// the exec call and before running any of its own code, it doesn't
	// matter which binary is exec'd as long as it exists and is runnable.
	cmd := exec.Command("/proc/self/exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	err := cmd.Start()
	if err == nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
	return err == nil
}

// Check returns an error if running containers under proot is not
// possible.
func Check() error {
	for _, name := range []string{"proot", "proot-init"} {
		if _, err := bin.FindBin(name); err != nil {
			return err
		}
	}
	if !HasWorkingPtrace() {
		return fmt.Errorf("proot requires the ptrace system call which is not usable")
	}
	return nil
}

// Use returns whether containers run under proot. requested is true when
// the user asked for proot, mode is the 'use proot' configuration directive
// and setuidUsable tells whether the setuid starter can be used instead of
// an unprivileged user namespace.
func Use(requested bool, mode string, setuidUsable bool) (bool, error) {
	if requested {
		if mode == ModeNo {
			return false, fmt.Errorf("--proot is disabled by configuration 'use proot = %s'", mode)
		}
		if os.Getuid() == 0 {
			return false, fmt.Errorf("--proot is only supported for unprivileged users")
		}
		return true, Check()
	}

	if os.Getuid() == 0 || mode == ModeNo {
		return false, nil
	}
	if mode == ModeAuto {
		if setuidUsable {
			return false, nil
		}
		reason := UserNamespaceUnusable(filepath.Join(buildcfg.LIBEXECDIR, "apptainer/bin/starter"))
		if reason == "" {
			return false, nil
		}
		sylog.Verbosef("%s", reason)
	}

	if err := Check(); err != nil {
		if mode == ModeYes {
			return false, err
		}
		sylog.Infof("Not using proot: %s", err)
		return false, nil
	}
	return true, nil
}

// Fusermount returns the path of the fusermount program used by FUSE
// filesystems to mount without privileges, as libfuse looks for it.
func Fusermount() (string, error) {
	for _, name := range []string{"fusermount3", "fusermount"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
		if path := filepath.Join("/usr/bin", name); fileExists(path) {
			return path, nil
		}
	}
	return "", fmt.Errorf("fusermount3 not found")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Automatic returns whether containers started by the current process run
// under proot when neither proot nor a user namespace is requested.
func Automatic() bool {
	conf := apptainerconf.GetCurrentConfig()
	if conf == nil {
		return false
	}
	if insideUserNs, _ := namespaces.IsInsideUserNamespace(os.Getpid()); insideUserNs {
		return false
	}
	setuidUsable := buildcfg.APPTAINER_SUID_INSTALL == 1 && conf.AllowSetuid
	use, err := Use(false, conf.UseProot, setuidUsable)
	return err == nil && use
}

func readSysctl(name string) string {
	b, err := os.ReadFile(filepath.Join(sysctlDir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// UserNamespaceUnusable returns the reason why the starter at starterPath
// can't use an unprivileged user namespace, or an empty string if it can.
func UserNamespaceUnusable(starterPath string) string {
	if readSysctl("kernel/unprivileged_userns_clone") == "0" {
		return "unprivileged user namespaces are disabled by kernel.unprivileged_userns_clone"
	}
	if readSysctl("user/max_user_namespaces") == "0" {
		return "user namespaces are disabled by user.max_user_namespaces"
	}
	if readSysctl("kernel/apparmor_restrict_unprivileged_userns") == "1" {
		if b, err := os.ReadFile(apparmorFlags); err == nil && strings.TrimSpace(string(b)) != "Y" {
			return ""
		}
		path, err := filepath.EvalSymlinks(starterPath)
		if err != nil {
			path = starterPath
		}
		if !apparmorAttached(apparmorDir, path) {
			return fmt.Sprintf("unprivileged user namespaces are restricted by AppArmor and no profile is attached to %s", path)
		}
	}
	return ""
}

// profileRe matches the attachment of an AppArmor profile, either named
// with an attachment or named after the attached path. The flags and the
// opening brace may be on the next line, but a path followed by anything
// else is a rule.
var profileRe = regexp.MustCompile(`^\s*(?:profile\s+\S+\s+(/\S+)|profile\s+(/\S+)|(/\S+)\s*(?:$|flags=|\{))`)

// apparmorAttached returns whether a profile in dir is attached to path.
// Profiles are only allowed to create user namespaces explicitly, but those
// attached to the starter are the ones installed for that purpose.
func apparmorAttached(dir, path string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		sylog.Debugf("Could not read AppArmor profiles: %s", err)
		return false
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		f, err := os.Open(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			m := profileRe.FindStringSubmatch(scanner.Text())
			if m == nil {
				continue
			}
			glob := m[1] + m[2] + m[3]
			if re, err := globRegexp(glob); err == nil && re.MatchString(path) {
				sylog.Debugf("AppArmor profile in %s is attached to %s", entry.Name(), path)
				f.Close()
				return true
			}
		}
		f.Close()
	}
	return false
}

// globRegexp converts an AppArmor path glob to a regular expression.
// Variables like @{multiarch} match any string.
func globRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); i++ {
		switch c := glob[i]; c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '{':
			b.WriteString("(?:")
		case '}':
			b.WriteString(")")
		case ',':
			b.WriteString("|")
		case '@':
			if end := strings.IndexByte(glob[i:], '}'); i+1 < len(glob) && glob[i+1] == '{' && end > 0 {
				b.WriteString(".*")
				i += end
			} else {
				b.WriteString(regexp.QuoteMeta(string(c)))
			}
		case '[', ']':
			b.WriteByte(c)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
