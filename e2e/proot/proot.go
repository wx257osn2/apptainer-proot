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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apptainer/apptainer/e2e/internal/e2e"
	"github.com/apptainer/apptainer/e2e/internal/testhelper"
	prootutil "github.com/apptainer/apptainer/internal/pkg/proot"
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
		"build":             c.testBuild,
	}
}
