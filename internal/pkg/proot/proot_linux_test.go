// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package proot

import (
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
)

func TestHasWorkingPtrace(t *testing.T) {
	// ptrace is expected to work in the environment running the unit
	// tests (no seccomp filter or similar restriction in place).
	if !HasWorkingPtrace() {
		t.Error("expected ptrace to work in the test environment")
	}
}

func TestGlobRegexp(t *testing.T) {
	tests := []struct {
		name  string
		glob  string
		path  string
		match bool
	}{
		{"exact", "/usr/libexec/apptainer/bin/starter", "/usr/libexec/apptainer/bin/starter", true},
		{"alternation", "/usr/libexec/apptainer/bin/starter{,-suid}", "/usr/libexec/apptainer/bin/starter-suid", true},
		{"alternation empty", "/usr/libexec/apptainer/bin/starter{,-suid}", "/usr/libexec/apptainer/bin/starter", true},
		{"nested alternation", "/usr/{bin/apptainer,libexec/apptainer/bin/starter{,-suid}}", "/usr/libexec/apptainer/bin/starter", true},
		{"nested alternation other", "/usr/{bin/apptainer,libexec/apptainer/bin/starter{,-suid}}", "/usr/bin/apptainer", true},
		{"nested alternation mismatch", "/usr/{bin/apptainer,libexec/apptainer/bin/starter{,-suid}}", "/usr/bin/starter", false},
		{"other path", "/usr/libexec/apptainer/bin/starter{,-suid}", "/home/user/apptainer/libexec/apptainer/bin/starter", false},
		{"star", "/opt/*/bin/starter", "/opt/apptainer/bin/starter", true},
		{"star no slash", "/opt/*/bin/starter", "/opt/a/b/bin/starter", false},
		{"double star", "/opt/**/starter", "/opt/a/b/bin/starter", true},
		{"variable", "/usr/lib/@{multiarch}/apptainer/bin/starter", "/usr/lib/x86_64-linux-gnu/apptainer/bin/starter", true},
		{"question mark", "/opt/app?/starter", "/opt/app1/starter", true},
		{"dot is literal", "/opt/a.b/starter", "/opt/axb/starter", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, err := globRegexp(tt.glob)
			assert.NilError(t, err)
			assert.Equal(t, re.MatchString(tt.path), tt.match)
		})
	}
}

func TestApparmorAttached(t *testing.T) {
	const starter = "/usr/libexec/apptainer/bin/starter"

	tests := []struct {
		name     string
		profiles map[string]string
		path     string
		attached bool
	}{
		{
			name: "named profile",
			profiles: map[string]string{
				"apptainer": "abi <abi/3.0>,\ninclude <tunables/global>\n\nprofile apptainer /usr/libexec/apptainer/bin/starter{,-suid} flags=(unconfined) {\n}\n",
			},
			path:     starter,
			attached: true,
		},
		{
			name: "named profile with flags on next line",
			profiles: map[string]string{
				"apptainer": "profile apptainer /usr/local/{bin/apptainer,libexec/apptainer/bin/starter{,-suid}}\n    flags=(unconfined) {\n  userns,\n}\n",
			},
			path:     "/usr/local/libexec/apptainer/bin/starter",
			attached: true,
		},
		{
			name: "rule is no attachment",
			profiles: map[string]string{
				"other": "profile other /usr/bin/other {\n  /usr/libexec/apptainer/bin/starter rix,\n}\n",
			},
			path:     starter,
			attached: false,
		},
		{
			name: "profile named after path",
			profiles: map[string]string{
				"starter": "/opt/apptainer/libexec/apptainer/bin/starter flags=(unconfined) {\n}\n",
			},
			path:     "/opt/apptainer/libexec/apptainer/bin/starter",
			attached: true,
		},
		{
			name: "profile for another path",
			profiles: map[string]string{
				"apptainer": "profile apptainer /usr/libexec/apptainer/bin/starter{,-suid} flags=(unconfined) {\n}\n",
			},
			path:     "/home/user/apptainer/libexec/apptainer/bin/starter",
			attached: false,
		},
		{
			name: "profile without attachment",
			profiles: map[string]string{
				"unprivileged_userns": "profile unprivileged_userns {\n  audit deny capability,\n}\n",
			},
			path:     starter,
			attached: false,
		},
		{
			name:     "no profile",
			profiles: map[string]string{},
			path:     starter,
			attached: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tt.profiles {
				assert.NilError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
			}
			assert.Equal(t, apparmorAttached(dir, tt.path), tt.attached)
		})
	}
}
