// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package apptainer

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"gotest.tools/v3/assert"
)

// newTestProotOps returns proot operations for a session directory laid
// out like the overlay session layout, and a host directory.
func newTestProotOps(t *testing.T) (o *prootOps, host string) {
	t.Helper()

	session, err := filepath.EvalSymlinks(t.TempDir())
	assert.NilError(t, err)
	host, err = filepath.EvalSymlinks(t.TempDir())
	assert.NilError(t, err)

	for _, dir := range []string{"rootfs", "final", "overlay-lowerdir"} {
		assert.NilError(t, os.Mkdir(filepath.Join(session, dir), 0o755))
	}
	o = newProotOps(session)
	o.rootFsPath = filepath.Join(session, "rootfs")
	o.finalPath = filepath.Join(session, "final")
	o.layerPath = filepath.Join(session, "overlay-lowerdir")
	return o, host
}

type testMount struct {
	source string
	target string
	fstype string
	flags  uintptr
}

func bindMount(source, target string) testMount {
	return testMount{source: source, target: target, flags: syscall.MS_BIND}
}

func rbindMount(source, target string) testMount {
	return testMount{source: source, target: target, flags: syscall.MS_BIND | syscall.MS_REC}
}

func TestProotMount(t *testing.T) {
	tests := []struct {
		name string
		// setup prepares the session (s) and host (h) directories and
		// returns the mounts to perform
		setup     func(t *testing.T, s, h string) []testMount
		wantBinds func(s, h string) []prootBind
		wantLinks func(s, h string) map[string]string
		wantErr   bool
	}{
		{
			name: "bind in container",
			setup: func(_ *testing.T, s, h string) []testMount {
				return []testMount{bindMount(h, s+"/final/mnt")}
			},
			wantBinds: func(_, h string) []prootBind {
				return []prootBind{{source: h, dest: "/mnt"}}
			},
		},
		{
			name: "remount and propagation ignored",
			setup: func(_ *testing.T, s, _ string) []testMount {
				return []testMount{
					{target: s + "/final/mnt", flags: syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY},
					{target: s + "/final", flags: syscall.MS_UNBINDABLE},
				}
			},
		},
		{
			name: "bind in session linked",
			setup: func(t *testing.T, s, h string) []testMount {
				assert.NilError(t, os.Mkdir(s+"/home", 0o755))
				return []testMount{bindMount(h, s+"/home")}
			},
			wantLinks: func(s, h string) map[string]string {
				return map[string]string{s + "/home": h}
			},
		},
		{
			name: "recursive bind carries session links",
			setup: func(t *testing.T, s, h string) []testMount {
				assert.NilError(t, os.Mkdir(s+"/dev", 0o755))
				assert.NilError(t, os.WriteFile(s+"/dev/null", nil, 0o644))
				assert.NilError(t, os.WriteFile(h+"/null", nil, 0o644))
				return []testMount{
					bindMount(h+"/null", s+"/dev/null"),
					rbindMount(s+"/dev", s+"/final/dev"),
				}
			},
			wantBinds: func(s, h string) []prootBind {
				return []prootBind{
					{source: s + "/dev", dest: "/dev"},
					{source: h + "/null", dest: "/dev/null"},
				}
			},
			wantLinks: func(s, h string) map[string]string {
				return map[string]string{s + "/dev/null": h + "/null"}
			},
		},
		{
			name: "recursive bind of host directory carries nothing",
			setup: func(t *testing.T, s, h string) []testMount {
				assert.NilError(t, os.Mkdir(s+"/home", 0o755))
				return []testMount{
					bindMount(h, s+"/home"),
					rbindMount(filepath.Dir(s), s+"/final/tmp"),
				}
			},
			wantBinds: func(s, _ string) []prootBind {
				return []prootBind{{source: filepath.Dir(s), dest: "/tmp"}}
			},
			wantLinks: func(s, h string) map[string]string {
				return map[string]string{s + "/home": h}
			},
		},
		{
			name: "bind through an emulated bind only recorded",
			setup: func(t *testing.T, s, h string) []testMount {
				assert.NilError(t, os.Mkdir(s+"/home", 0o755))
				return []testMount{
					bindMount(h, s+"/home"),
					bindMount("/proc", s+"/home/proc"),
				}
			},
			wantLinks: func(s, h string) map[string]string {
				return map[string]string{s + "/home": h, s + "/home/proc": "/proc"}
			},
		},
		{
			name: "bind on non empty session directory",
			setup: func(t *testing.T, s, h string) []testMount {
				assert.NilError(t, os.MkdirAll(s+"/busy/content", 0o755))
				return []testMount{bindMount(h, s+"/busy")}
			},
			wantErr: true,
		},
		{
			name: "bind outside of session",
			setup: func(_ *testing.T, _, h string) []testMount {
				return []testMount{bindMount("/proc", h+"/proc")}
			},
			wantErr: true,
		},
		{
			name: "kernel filesystems in container",
			setup: func(_ *testing.T, s, _ string) []testMount {
				return []testMount{
					{source: "proc", target: s + "/final/proc", fstype: "proc"},
					{source: "sysfs", target: s + "/final/sys", fstype: "sysfs"},
				}
			},
			wantBinds: func(_, _ string) []prootBind {
				return []prootBind{
					{source: "/proc", dest: "/proc"},
					{source: "/sys", dest: "/sys"},
				}
			},
		},
		{
			name: "tmpfs in container",
			setup: func(_ *testing.T, s, _ string) []testMount {
				return []testMount{{source: "tmpfs", target: s + "/final/tmp", fstype: "tmpfs"}}
			},
			wantBinds: func(s, _ string) []prootBind {
				return []prootBind{{source: s + "/proot/tmpfs/0", dest: "/tmp"}}
			},
		},
		{
			name: "unsupported filesystem",
			setup: func(_ *testing.T, s, _ string) []testMount {
				return []testMount{{source: "none", target: s + "/final/x", fstype: "cgroup2"}}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, h := newTestProotOps(t)
			s := o.sessionPath

			var err error
			for _, m := range tt.setup(t, s, h) {
				if err = o.Mount(m.source, m.target, m.fstype, m.flags, ""); err != nil {
					break
				}
			}
			if tt.wantErr {
				assert.Assert(t, err != nil)
				return
			}
			assert.NilError(t, err)

			var wantBinds []prootBind
			if tt.wantBinds != nil {
				wantBinds = tt.wantBinds(s, h)
			}
			assert.Assert(t, reflect.DeepEqual(o.binds, wantBinds), "binds %v, want %v", o.binds, wantBinds)

			wantLinks := map[string]string{}
			if tt.wantLinks != nil {
				wantLinks = tt.wantLinks(s, h)
			}
			assert.DeepEqual(t, o.links, wantLinks)

			// the host directory is never modified
			entries, err := os.ReadDir(h)
			assert.NilError(t, err)
			for _, e := range entries {
				assert.Assert(t, e.Name() == "null", "unexpected %s in host directory", e.Name())
			}
		})
	}
}

func TestProotLinkReplacesPlaceholder(t *testing.T) {
	o, h := newTestProotOps(t)
	s := o.sessionPath
	assert.NilError(t, os.Mkdir(s+"/home", 0o755))

	assert.NilError(t, o.Mount(h, s+"/home", "", syscall.MS_BIND, ""))
	target, err := os.Readlink(s + "/home")
	assert.NilError(t, err)
	assert.Equal(t, target, h)
}

func TestProotOverlay(t *testing.T) {
	tests := []struct {
		name    string
		data    func(o *prootOps) string
		wantErr error
	}{
		{
			name: "read-only session overlay",
			data: func(o *prootOps) string {
				return "lowerdir=" + o.layerPath + ":" + o.rootFsPath
			},
		},
		{
			name: "writable overlay",
			data: func(o *prootOps) string {
				return "lowerdir=" + o.layerPath + ":" + o.rootFsPath + ",upperdir=/u,workdir=/w,xino=on"
			},
			wantErr: errProotOverlay,
		},
		{
			name: "overlay image",
			data: func(o *prootOps) string {
				return "lowerdir=/image:" + o.layerPath + ":" + o.rootFsPath
			},
			wantErr: errProotOverlay,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, _ := newTestProotOps(t)
			err := o.Mount("overlay", o.finalPath, "overlay", syscall.MS_NODEV, tt.data(o))
			if tt.wantErr != nil {
				assert.Assert(t, errors.Is(err, tt.wantErr))
				assert.Assert(t, !o.emulatedOverlay)
				return
			}
			assert.NilError(t, err)
			assert.Assert(t, o.emulatedOverlay)
			target, err := os.Readlink(o.finalPath)
			assert.NilError(t, err)
			assert.Equal(t, target, o.rootFsPath)
		})
	}
}

func TestProotGuestBinds(t *testing.T) {
	o, h := newTestProotOps(t)
	s := o.sessionPath
	assert.NilError(t, o.Mount("overlay", o.finalPath, "overlay", 0, "lowerdir="+o.layerPath+":"+o.rootFsPath))

	// session layer entries: a mount point directory, a mount point
	// file and a symbolic link bound in place
	assert.NilError(t, os.MkdirAll(o.layerPath+"/mnt", 0o755))
	assert.NilError(t, os.MkdirAll(o.layerPath+"/etc", 0o755))
	assert.NilError(t, os.WriteFile(o.layerPath+"/etc/hosts", nil, 0o644))
	assert.NilError(t, os.WriteFile(h+"/resolv.conf", nil, 0o644))
	assert.NilError(t, os.Symlink(h+"/resolv.conf", o.layerPath+"/etc/resolv.conf"))

	// a staged /dev directory with a device placeholder
	assert.NilError(t, os.Mkdir(s+"/dev", 0o755))
	assert.NilError(t, os.WriteFile(s+"/dev/null", nil, 0o644))

	for _, m := range []testMount{
		bindMount("/etc/hosts", o.finalPath+"/etc/hosts"),
		bindMount("/dev/null", s+"/dev/null"),
		rbindMount(s+"/dev", o.finalPath+"/dev"),
		bindMount(h, o.finalPath+"/mnt"),
		bindMount("/proc", o.finalPath+"/mnt"),
	} {
		assert.NilError(t, o.Mount(m.source, m.target, m.fstype, m.flags, ""))
	}

	binds, err := o.guestBinds()
	assert.NilError(t, err)
	want := []prootBind{
		{source: h + "/resolv.conf", dest: "/etc/resolv.conf"},
		{source: "/etc/hosts", dest: "/etc/hosts"},
		{source: s + "/dev", dest: "/dev"},
		{source: "/dev/null", dest: "/dev/null"},
		{source: "/proc", dest: "/mnt"},
	}
	assert.Assert(t, reflect.DeepEqual(binds, want), "binds %v, want %v", binds, want)

	// the link carried by the bound /dev directory is a placeholder again
	fi, err := os.Lstat(s + "/dev/null")
	assert.NilError(t, err)
	assert.Assert(t, fi.Mode().IsRegular())
}

func TestProotLayeredPath(t *testing.T) {
	o, _ := newTestProotOps(t)
	assert.NilError(t, o.Mount("overlay", o.finalPath, "overlay", 0, "lowerdir="+o.layerPath+":"+o.rootFsPath))
	assert.NilError(t, os.MkdirAll(o.layerPath+"/work/dir", 0o755))

	_, err := o.Stat(o.finalPath + "/work/dir")
	assert.NilError(t, err)
	_, err = o.Stat(o.finalPath + "/missing")
	assert.Assert(t, os.IsNotExist(err))
}
