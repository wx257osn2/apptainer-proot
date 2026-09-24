// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

// Package proot tests running and building containers under proot, without
// namespaces.
package proot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apptainer/apptainer/e2e/internal/e2e"
	"github.com/apptainer/apptainer/e2e/internal/testhelper"
	prootutil "github.com/apptainer/apptainer/internal/pkg/proot"
	"github.com/apptainer/apptainer/internal/pkg/test/tool/require"
)

type ctx struct {
	env e2e.TestEnv
}

func requireProot(t *testing.T) {
	if err := prootutil.Check(); err != nil {
		t.Skipf("proot not usable: %s", err)
	}
}

func (c ctx) testActions(t *testing.T) {
	requireProot(t)
	e2e.EnsureImage(t, c.env)

	tmpDir, cleanup := e2e.MakeTempDir(t, c.env.TestDir, "proot-actions-", "")
	t.Cleanup(func() {
		if !t.Failed() {
			cleanup(t)
		}
	})
	overlayDir := filepath.Join(tmpDir, "overlay")
	if err := os.Mkdir(overlayDir, 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		exit int
		ops  []e2e.ApptainerCmdResultOp
	}{
		{
			name: "exec",
			args: []string{c.env.ImagePath, "true"},
		},
		{
			name: "exit status",
			args: []string{c.env.ImagePath, "/bin/sh", "-c", "exit 3"},
			exit: 3,
		},
		{
			name: "failed process in pipeline",
			args: []string{c.env.ImagePath, "/bin/sh", "-c", "false | true"},
		},
		{
			name: "user",
			args: []string{c.env.ImagePath, "id", "-u"},
			ops:  []e2e.ApptainerCmdResultOp{e2e.ExpectOutputf(e2e.ExactMatch, "%d", e2e.UserProfile.ContainerUser(t).UID)},
		},
		{
			name: "environment",
			args: []string{"--env", "PROOT_TEST=value", c.env.ImagePath, "/bin/sh", "-c", "echo $PROOT_TEST $AVENGERS"},
			ops:  []e2e.ApptainerCmdResultOp{e2e.ExpectOutput(e2e.ExactMatch, "value assemble")},
		},
		{
			name: "read-only root filesystem",
			args: []string{c.env.ImagePath, "touch", "/proot-file"},
			exit: 1,
		},
		{
			name: "writable tmpfs",
			args: []string{"--writable-tmpfs", c.env.ImagePath, "touch", "/proot-file"},
		},
		{
			name: "overlay directory",
			args: []string{"--overlay", overlayDir, c.env.ImagePath, "touch", "/proot-file"},
		},
		{
			name: "bind to missing destination",
			args: []string{"--bind", tmpDir + ":/proot/missing", c.env.ImagePath, "test", "-d", "/proot/missing/overlay"},
		},
		{
			name: "contain",
			args: []string{"--contain", c.env.ImagePath, "/bin/sh", "-c", "test -c /dev/null && test ! -e /dev/mem"},
		},
		{
			name: "fakeroot",
			args: []string{"--fakeroot", c.env.ImagePath, "id", "-u"},
			ops:  []e2e.ApptainerCmdResultOp{e2e.ExpectOutput(e2e.ExactMatch, "0")},
		},
		{
			name: "unsupported namespace",
			args: []string{"--pid", c.env.ImagePath, "true"},
			exit: 255,
			ops:  []e2e.ApptainerCmdResultOp{e2e.ExpectError(e2e.ContainMatch, "--pid not supported with proot")},
		},
	}

	for _, tt := range tests {
		c.env.RunApptainer(
			t,
			e2e.AsSubtest(tt.name),
			e2e.WithProfile(e2e.UserProfile),
			e2e.WithCommand("exec"),
			e2e.WithArgs(append([]string{"--proot"}, tt.args...)...),
			e2e.ExpectExit(tt.exit, tt.ops...),
		)
	}

	if _, err := os.Stat(filepath.Join(overlayDir, "upper", "proot-file")); err != nil {
		t.Errorf("file not written in overlay directory: %s", err)
	}
}

// testSandboxUntouched checks that proot doesn't create bind destinations
// in a sandbox, which may be used by other containers at the same time.
func (c ctx) testSandboxUntouched(t *testing.T) {
	requireProot(t)
	e2e.EnsureImage(t, c.env)

	tmpDir, cleanup := e2e.MakeTempDir(t, c.env.TestDir, "proot-sandbox-", "")
	t.Cleanup(func() {
		if !t.Failed() {
			cleanup(t)
		}
	})
	sandbox := filepath.Join(tmpDir, "sandbox")

	c.env.RunApptainer(
		t,
		e2e.WithProfile(e2e.UserProfile),
		e2e.WithCommand("build"),
		e2e.WithArgs("--sandbox", sandbox, c.env.ImagePath),
		e2e.ExpectExit(0),
	)

	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(sandbox, past, past); err != nil {
		t.Fatal(err)
	}

	c.env.RunApptainer(
		t,
		e2e.WithProfile(e2e.UserProfile),
		e2e.WithCommand("exec"),
		e2e.WithArgs("--proot", "--bind", tmpDir+":/proot-mnt", sandbox, "test", "-d", "/proot-mnt/sandbox"),
		e2e.ExpectExit(0),
	)

	fi, err := os.Stat(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(past) {
		t.Errorf("sandbox root directory was modified at %s", fi.ModTime())
	}
	if _, err := os.Lstat(filepath.Join(sandbox, "proot-mnt")); err == nil {
		t.Errorf("bind destination left in sandbox")
	}
}

// testPathTranslation checks system calls whose paths proot translates,
// through programs of the Debian image using them.
func (c ctx) testPathTranslation(t *testing.T) {
	requireProot(t)
	e2e.EnsureDebianImage(t, c.env)

	tmpDir, cleanup := e2e.MakeTempDir(t, c.env.TestDir, "proot-paths-", "")
	t.Cleanup(func() {
		if !t.Failed() {
			cleanup(t)
		}
	})

	// run runs script in its own /work directory, the working directory.
	nbWorkDirs := 0
	run := func(t *testing.T, profile e2e.Profile, proot bool, script string, ops ...e2e.ApptainerCmdOp) {
		nbWorkDirs++
		workDir := filepath.Join(tmpDir, fmt.Sprint(nbWorkDirs))
		if err := os.Mkdir(workDir, 0o755); err != nil {
			t.Fatal(err)
		}
		args := []string{"--bind", workDir + ":/work", "--pwd", "/work", c.env.DebianImagePath, "bash", "-c", script}
		if proot {
			args = append([]string{"--proot"}, args...)
		}
		c.env.RunApptainer(
			t,
			append([]e2e.ApptainerCmdOp{
				e2e.WithProfile(profile),
				e2e.WithCommand("exec"),
				e2e.WithArgs(args...),
			}, ops...)...,
		)
	}

	tests := []struct {
		name   string
		script string
	}{
		{
			name:   "tar relative to working directory",
			script: "mkdir -p a/b/c && echo x >a/b/c/f && tar -cf t.tar a && rm -r a && tar -xf t.tar && test -f a/b/c/f",
		},
		{
			name:   "test -x relative to working directory",
			script: "cd /usr/bin && test -x env",
		},
	}
	for _, tt := range tests {
		run(t, e2e.UserProfile, true, tt.script, e2e.AsSubtest(tt.name), e2e.ExpectExit(0))
	}

	// GNU tar refuses a symlink out of the directory it extracts to when it
	// opens directories with openat2, which depends on the patches of the
	// distribution, so the result in a user namespace is the reference.
	t.Run("tar through symlink out of extraction directory", func(t *testing.T) {
		require.UserNamespace(t)
		script := "mkdir -p src/esc out outside && echo x >src/esc/f && tar -C src -cf e.tar esc/f && " +
			"ln -s /work/outside out/esc && cd out && tar -xf ../e.tar 2>../err; " +
			"echo \"status $? escaped '$(ls ../outside)' $(head -n 1 ../err)\""
		var expected, stderr string
		run(t, e2e.UserNamespaceProfile, false, script, e2e.ExpectExit(0, e2e.GetStreams(&expected, &stderr)))
		run(t, e2e.UserProfile, true, script,
			e2e.ExpectExit(0, e2e.ExpectOutput(e2e.ExactMatch, strings.TrimSuffix(expected, "\n"))))
	})
}

func (c ctx) testBuild(t *testing.T) {
	requireProot(t)
	e2e.EnsureImage(t, c.env)

	tmpDir, cleanup := e2e.MakeTempDir(t, c.env.TestDir, "proot-build-", "")
	t.Cleanup(func() {
		if !t.Failed() {
			cleanup(t)
		}
	})

	def := filepath.Join(tmpDir, "proot.def")
	content := "Bootstrap: localimage\nFrom: " + c.env.ImagePath + "\n\n" +
		"%post\n    test \"$(id -u)\" = 0\n    touch /built\n\n" +
		"%test\n    test -f /built\n"
	if err := os.WriteFile(def, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(tmpDir, "proot.sif")

	c.env.RunApptainer(
		t,
		e2e.WithProfile(e2e.UserProfile),
		e2e.WithCommand("build"),
		e2e.WithArgs("--proot", image, def),
		e2e.ExpectExit(0),
	)

	c.env.RunApptainer(
		t,
		e2e.WithProfile(e2e.UserProfile),
		e2e.WithCommand("exec"),
		e2e.WithArgs("--proot", image, "test", "-f", "/built"),
		e2e.ExpectExit(0),
	)
}

// E2ETests is the main func to trigger the test suite
func E2ETests(env e2e.TestEnv) testhelper.Tests {
	c := ctx{
		env: env,
	}

	return testhelper.Tests{
		"actions":           c.testActions,
		"sandbox untouched": c.testSandboxUntouched,
		"path translation":  c.testPathTranslation,
		"build":             c.testBuild,
	}
}
