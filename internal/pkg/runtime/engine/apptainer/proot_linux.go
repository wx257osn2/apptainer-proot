// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package apptainer

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	prootutil "github.com/apptainer/apptainer/internal/pkg/proot"
	"github.com/apptainer/apptainer/internal/pkg/runtime/engine/config/starter"
	"github.com/apptainer/apptainer/internal/pkg/util/bin"
	"github.com/apptainer/apptainer/internal/pkg/util/fs/layout"
	"github.com/apptainer/apptainer/internal/pkg/util/mainthread"
	"github.com/apptainer/apptainer/pkg/build/types"
	"github.com/apptainer/apptainer/pkg/image"
	apptainerConfig "github.com/apptainer/apptainer/pkg/runtime/engine/apptainer/config"
	"github.com/apptainer/apptainer/pkg/runtime/engine/config"
	"github.com/apptainer/apptainer/pkg/sylog"
	"github.com/apptainer/apptainer/pkg/util/fs/proc"
	"github.com/ccoveille/go-safecast/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// prootInitDest is the container path of the proot-init helper.
const prootInitDest = "/.singularity.d/proot-init"

// errProotOverlay reports an overlay which can't be emulated with proot
// bindings, the engine falls back to the overlay image driver.
var errProotOverlay = errors.New("overlay requires the overlay image driver with proot")

// prootBind is a bind mount performed by proot in the container.
type prootBind struct {
	source string // host path
	dest   string // container path
}

// prootOps implements containerOps without namespaces. Bind mounts inside
// the session directory are emulated with symbolic links so the engine
// sees them, bind mounts inside the container root filesystem become proot
// bindings. Image and overlay filesystems are real FUSE mounts done by the
// image driver.
type prootOps struct {
	layout.VFS
	sessionPath     string
	finalPath       string
	rootFsPath      string
	layerPath       string
	emulatedOverlay bool
	// links maps emulated bind targets in the session directory to their
	// source, including binds carried by recursive binds of directories
	// containing them.
	links      map[string]string
	binds      []prootBind
	cwd        string
	root       string
	tmpfsCount int
}

func newProotOps(sessionPath string) *prootOps {
	return &prootOps{
		VFS:         layout.DefaultVFS,
		sessionPath: sessionPath,
		links:       make(map[string]string),
	}
}

// setSession records the session layout paths once it has been created.
func (o *prootOps) setSession(s *layout.Session) {
	o.finalPath = s.FinalPath()
	o.rootFsPath = s.RootFsPath()
	if s.Layer != nil {
		o.layerPath, _ = s.GetPath(s.Layer.Dir())
	}
}

// isUnder returns whether path is dir or is located under dir.
func isUnder(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// inContainer returns whether target is a path inside the container root
// filesystem, which is then a proot binding.
func (o *prootOps) inContainer(target string) bool {
	return o.finalPath != "" && target != o.finalPath && isUnder(target, o.finalPath)
}

func (o *prootOps) Mount(source string, target string, filesystem string, flags uintptr, data string) error {
	switch {
	case flags&syscall.MS_REMOUNT != 0:
		return nil
	case flags&syscall.MS_BIND != 0:
		return o.bind(source, target, flags&syscall.MS_REC != 0)
	case flags&(syscall.MS_SHARED|syscall.MS_SLAVE|syscall.MS_PRIVATE|syscall.MS_UNBINDABLE) != 0:
		return nil
	}

	switch filesystem {
	case "tmpfs":
		return o.tmpfs(target, data)
	case "proc":
		return o.bind("/proc", target, true)
	case "sysfs":
		return o.bind("/sys", target, true)
	case "devpts":
		return o.bind("/dev/pts", target, true)
	case "mqueue":
		return o.bind("/dev/mqueue", target, true)
	case "overlay":
		return o.overlay(target, data)
	}
	return fmt.Errorf("%s filesystem is not supported with proot", filesystem)
}

func (o *prootOps) bind(source, target string, recursive bool) error {
	if source == target {
		return nil
	}
	src, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}

	if o.inContainer(target) {
		dest := strings.TrimPrefix(target, o.finalPath)
		o.binds = append(o.binds, prootBind{source: src, dest: dest})
		if recursive && isUnder(source, o.sessionPath) {
			for _, l := range o.linksUnder(source) {
				o.binds = append(o.binds, prootBind{source: l.source, dest: dest + l.dest})
			}
		}
		return nil
	}

	if !isUnder(target, o.sessionPath) {
		return fmt.Errorf("bind target %s is outside of session directory %s", target, o.sessionPath)
	}
	return o.link(src, source, target, recursive)
}

// linksUnder returns the emulated binds located under dir, with their
// destination relative to dir. Only binds of session directories carry
// emulated binds, the session directory can't be reached from the host
// in the container.
func (o *prootOps) linksUnder(dir string) []prootBind {
	var links []prootBind
	for target, source := range o.links {
		if target != dir && isUnder(target, dir) {
			links = append(links, prootBind{source: source, dest: strings.TrimPrefix(target, dir)})
		}
	}
	return links
}

// link emulates the bind of source on target located in the session
// directory by replacing the placeholder target with a symbolic link to src,
// the resolved source.
func (o *prootOps) link(src, source, target string, recursive bool) error {
	if recursive && isUnder(source, o.sessionPath) {
		for _, l := range o.linksUnder(source) {
			o.links[target+l.dest] = l.source
		}
	}
	o.links[target] = src

	// A target reached through another emulated bind lies outside of the
	// session directory, it is only recorded for the binds carrying it.
	dir, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil || dir != filepath.Dir(target) {
		sylog.Debugf("Not linking %s to %s: located in an emulated bind", target, src)
		return nil
	}

	fi, err := os.Lstat(target)
	if err == nil {
		switch mode := fi.Mode(); {
		case mode.IsDir(), mode&fs.ModeSymlink != 0, mode.IsRegular() && fi.Size() == 0:
			if err := os.Remove(target); err != nil {
				return fmt.Errorf("while replacing %s by a link to %s: %w", target, src, err)
			}
		default:
			return fmt.Errorf("can't replace %s by a link to %s", target, src)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	sylog.Debugf("Linking %s to %s", target, src)
	return os.Symlink(src, target)
}

func (o *prootOps) tmpfs(target, data string) error {
	var mode os.FileMode
	for _, opt := range strings.Split(data, ",") {
		if m, ok := strings.CutPrefix(opt, "mode="); ok {
			perm, err := strconv.ParseUint(m, 8, 32)
			if err != nil {
				return fmt.Errorf("bad tmpfs mode %s: %w", m, err)
			}
			perm32, err := safecast.Convert[uint32](perm)
			if err != nil {
				return err
			}
			mode = os.FileMode(perm32&0o777) | unixModeBits(perm)
		}
	}

	if target == o.sessionPath {
		return nil
	}

	dir := target
	if o.inContainer(target) {
		dir = filepath.Join(o.sessionPath, "proot", "tmpfs", strconv.Itoa(o.tmpfsCount))
		o.tmpfsCount++
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if mode != 0 {
		if err := os.Chmod(dir, mode); err != nil {
			return err
		}
	}
	if dir == target {
		return nil
	}
	return o.bind(dir, target, false)
}

// unixModeBits converts the setuid, setgid and sticky bits of a numeric
// mode to os.FileMode bits.
func unixModeBits(perm uint64) os.FileMode {
	var mode os.FileMode
	if perm&unix.S_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if perm&unix.S_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	if perm&unix.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

// overlay emulates the read-only session overlay made of the session layer
// directory on top of the root filesystem: missing mount points are created
// by proot and the layer files are bound at launch.
func (o *prootOps) overlay(target, data string) error {
	var lowers []string
	upper := ""
	for _, opt := range strings.Split(data, ",") {
		if v, ok := strings.CutPrefix(opt, "lowerdir="); ok {
			lowers = strings.Split(v, ":")
		} else if v, ok := strings.CutPrefix(opt, "upperdir="); ok {
			upper = v
		}
	}
	if upper != "" || len(lowers) != 2 || lowers[0] != o.layerPath || lowers[1] != o.rootFsPath {
		return errProotOverlay
	}
	o.emulatedOverlay = true
	return o.link(o.rootFsPath, o.rootFsPath, target, false)
}

func (o *prootOps) Unmount(target string, _ int) error {
	return fmt.Errorf("unmount of %s is not supported with proot", target)
}

func (o *prootOps) Decrypt(uint64, string, []byte, int) (string, error) {
	return "", errors.New("encrypted images are not supported with proot")
}

func (o *prootOps) Chroot(root string, _ string) (int, error) {
	if root == "." {
		root = o.cwd
	}
	o.root = root
	return 0, nil
}

func (o *prootOps) LoopDevice(string, int, unix.LoopInfo64, int, bool) (int, error) {
	return -1, errors.New("loop devices are not supported with proot")
}

func (o *prootOps) SetHostname(string) (int, error) {
	return -1, errors.New("setting the hostname is not supported with proot")
}

func (o *prootOps) Chdir(dir string) (int, error) {
	o.cwd = dir
	return 0, nil
}

// layeredPath returns the path in the session layer directory emulating the
// overlay for path in the container, if it exists there.
func (o *prootOps) layeredPath(path string) string {
	if o.emulatedOverlay && o.inContainer(path) {
		layered := o.layerPath + strings.TrimPrefix(path, o.finalPath)
		if _, err := os.Lstat(layered); err == nil {
			return layered
		}
	}
	return path
}

func (o *prootOps) Stat(path string) (os.FileInfo, error) {
	return os.Stat(o.layeredPath(path))
}

func (o *prootOps) Lstat(path string) (os.FileInfo, error) {
	return os.Lstat(o.layeredPath(path))
}

func (o *prootOps) Access(path string, mode uint32) error {
	return unix.Access(o.layeredPath(path), mode)
}

func (o *prootOps) SendFuseFd(int, []int) error {
	return errors.New("FUSE mounts are not supported with proot")
}

func (o *prootOps) OpenSendFuseFd(int) (int, error) {
	return -1, errors.New("FUSE mounts are not supported with proot")
}

func (o *prootOps) NvCCLI([]string, string, bool) error {
	return errors.New("nvidia-container-cli is not supported with proot")
}

func (o *prootOps) OciHook(specs.Hook, specs.State) error {
	return errors.New("CDI device hooks are not supported with proot")
}

// unlinkBound replaces the symbolic links emulating binds under the session
// directories bound in the container by placeholders: proot resolves the
// bindings carried with those directories through them, from the container,
// where the symbolic link targets are wrong.
func (o *prootOps) unlinkBound() error {
	for _, b := range o.binds {
		if !isUnder(b.source, o.sessionPath) {
			continue
		}
		for target, source := range o.links {
			if target == b.source || !isUnder(target, b.source) {
				continue
			}
			fi, err := os.Lstat(target)
			if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
				continue
			}
			if err := os.Remove(target); err != nil {
				return err
			}
			if isDir(source) {
				err = os.Mkdir(target, 0o755)
			} else {
				err = os.WriteFile(target, nil, 0o644)
			}
			if err != nil {
				return fmt.Errorf("while replacing link %s by a placeholder: %w", target, err)
			}
		}
	}
	return nil
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// guestBinds returns the proot bindings, a later binding replacing an
// earlier one with the same destination as a mount would.
func (o *prootOps) guestBinds() ([]prootBind, error) {
	if err := o.unlinkBound(); err != nil {
		return nil, err
	}
	binds := o.binds
	if o.emulatedOverlay && o.layerPath != "" {
		// Files the session layer adds on top of the root filesystem,
		// like the /etc/resolv.conf symlink, are bound in place. Those
		// which are bind targets are already covered.
		err := filepath.WalkDir(o.layerPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			src, err := filepath.EvalSymlinks(path)
			if err != nil {
				sylog.Debugf("Skipping session layer file %s: %s", path, err)
				return nil
			}
			dest := strings.TrimPrefix(path, o.layerPath)
			binds = append([]prootBind{{source: src, dest: dest}}, binds...)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("while reading session layer: %w", err)
		}
	}

	seen := make(map[string]bool)
	deduped := make([]prootBind, 0, len(binds))
	for i := len(binds) - 1; i >= 0; i-- {
		if seen[binds[i].dest] {
			continue
		}
		seen[binds[i].dest] = true
		deduped = append([]prootBind{binds[i]}, deduped...)
	}
	return deduped, nil
}

// ProotRun sets up the container described by cfg without any namespace
// and executes its process under proot, from the current process. It
// returns the wait status of the container process.
func ProotRun(ctx context.Context, cfg *config.Common) (syscall.WaitStatus, error) {
	// The engine gets its configuration through JSON from the starter,
	// which also binds the OCI generator to the OCI spec.
	data, err := json.Marshal(cfg.EngineConfig)
	if err != nil {
		return 0, fmt.Errorf("while encoding engine configuration: %w", err)
	}
	engineConfig := apptainerConfig.NewConfig()
	if err := json.Unmarshal(data, engineConfig); err != nil {
		return 0, fmt.Errorf("while decoding engine configuration: %w", err)
	}
	common := *cfg
	common.EngineConfig = engineConfig

	e := &EngineOperations{EngineConfig: engineConfig}
	e.InitConfig(&common, false)

	prootPath, err := bin.FindBin("proot")
	if err != nil {
		return 0, err
	}
	initPath, err := bin.FindBin("proot-init")
	if err != nil {
		return 0, err
	}

	// engine code expects functions to be executed by the main thread
	// of the starter process
	go func() {
		for f := range mainthread.FuncChannel {
			f()
		}
	}()

	sessionPath, err := os.MkdirTemp(e.EngineConfig.GetTmpDir(), "apptainer-proot-")
	if err != nil {
		return 0, fmt.Errorf("while creating session directory: %w", err)
	}
	// mount points are compared with the resolved path during removal
	resolved, err := filepath.EvalSymlinks(sessionPath)
	if err != nil {
		os.Remove(sessionPath)
		return 0, err
	}
	sessionPath = resolved
	defer removeProotSession(sessionPath)

	// images opened by the caller are closed, as they would be by the
	// starter execution
	image.ResetLockTracking()
	//nolint:contextcheck // PrepareConfig is the stage 1 entry point which has no context
	if err := e.PrepareConfig(starter.NewLocalConfig()); err != nil {
		return 0, err
	}

	ops := newProotOps(sessionPath)
	err = create(ctx, e, ops, os.Getpid())
	var status syscall.WaitStatus
	if err == nil {
		status, err = e.runProot(ops, prootPath, initPath, sessionPath)
	}
	if cerr := e.CleanupContainer(ctx, err, status); cerr != nil && err == nil {
		err = cerr
	}
	return status, err
}

// runProot executes proot-init under proot in the container and waits for
// it, forwarding signals when required.
func (e *EngineOperations) runProot(ops *prootOps, prootPath, initPath, sessionPath string) (syscall.WaitStatus, error) {
	root, err := filepath.EvalSymlinks(ops.root)
	if err != nil {
		return 0, fmt.Errorf("while resolving container root filesystem: %w", err)
	}
	binds, err := ops.guestBinds()
	if err != nil {
		return 0, err
	}

	args := []string{"--kill-on-exit", "-r", root, "-w", "/"}
	if e.EngineConfig.GetFakeroot() {
		args = append(args, "-0")
	}
	for _, b := range binds {
		args = append(args, "-b", b.source+":"+b.dest)
	}
	args = append(args, "-b", initPath+":"+prootInitDest, prootInitDest)

	prootTmp := filepath.Join(sessionPath, "proot", "tmp")
	if err := os.MkdirAll(prootTmp, 0o700); err != nil {
		return 0, err
	}

	configRead, configWrite, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer configWrite.Close()
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer statusRead.Close()

	sylog.Debugf("Executing %s %s", prootPath, strings.Join(args, " "))
	cmd := exec.Command(prootPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{configRead, statusWrite}
	// Without PROOT_DONT_POLLUTE_ROOTFS, proot creates missing bind
	// destinations in a writable root filesystem, such as a sandbox shared
	// with other containers, instead of in its temporary directory.
	cmd.Env = []string{"PROOT_TMP_DIR=" + prootTmp, "PROOT_DONT_POLLUTE_ROOTFS=1", sylog.GetEnvVar()}
	cmd.Env = append(cmd.Env, prootLoaderEnv(prootPath)...)

	signals := make(chan os.Signal, 16)
	signal.Notify(signals)
	defer signal.Stop(signals)

	err = cmd.Start()
	configRead.Close()
	statusWrite.Close()
	if err != nil {
		return 0, fmt.Errorf("while starting proot: %w", err)
	}

	go func() {
		if err := json.NewEncoder(configWrite).Encode(e.EngineConfig); err != nil {
			sylog.Debugf("While sending engine configuration: %s", err)
		}
		configWrite.Close()
	}()

	// proot-init reports the PID, then the wait status of the container
	// process
	pidCh := make(chan int, 1)
	statusCh := make(chan syscall.WaitStatus, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(statusRead)
		if scanner.Scan() {
			pid, _ := strconv.Atoi(scanner.Text())
			pidCh <- pid
		}
		if scanner.Scan() {
			status, err := strconv.ParseUint(scanner.Text(), 10, 32)
			if err == nil {
				statusCh <- syscall.WaitStatus(status)
			}
		}
	}()

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	pid := 0
	for {
		select {
		case pid = <-pidCh:
		case s := <-signals:
			switch s {
			case syscall.SIGCHLD, syscall.SIGURG:
				continue
			}
			if e.EngineConfig.GetSignalPropagation() && pid > 0 {
				if err := syscall.Kill(pid, s.(syscall.Signal)); err != nil {
					sylog.Debugf("While forwarding %s to %d: %s", s, pid, err)
				}
			}
			// stop ourself so the parent process gets SIGCHLD, as
			// the container process does
			if s == syscall.SIGTSTP {
				if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil {
					sylog.Debugf("While stopping: %s", err)
				}
			}
		case err := <-waitCh:
			var exitErr *exec.ExitError
			if err != nil && !errors.As(err, &exitErr) {
				return 0, fmt.Errorf("while waiting for proot: %w", err)
			}
			// all writers exited with proot
			<-readDone
			select {
			case status := <-statusCh:
				return status, nil
			default:
				// proot-init failed before running the container
				// process
				return cmd.ProcessState.Sys().(syscall.WaitStatus), nil
			}
		}
	}
}

// prootLoaders are the proot environment variables selecting the loaders,
// and the name of the loaders installed next to the bundled proot. There is
// no 32-bit loader on architectures without 32-bit support in proot.
var prootLoaders = []struct {
	env  string
	name string
}{
	{"PROOT_LOADER", "proot-loader"},
	{"PROOT_LOADER_32", "proot-loader-m32"},
}

// prootLoaderEnv returns the environment selecting the loaders installed
// next to proot, if any, otherwise proot extracts its own. Proot executes
// its loader in place of each program, so the kernel records the loader
// path as the executed path, from which uutils coreutils choose the utility
// to run: the path is given under /proc for them to use argv[0] instead.
func prootLoaderEnv(prootPath string) []string {
	dir, err := filepath.Abs(filepath.Dir(prootPath))
	if err != nil {
		return nil
	}
	var env []string
	for _, l := range prootLoaders {
		loader := filepath.Join(dir, l.name)
		if fi, err := os.Stat(loader); err == nil && fi.Mode().IsRegular() {
			env = append(env, l.env+"=/proc/self/root"+loader)
		}
	}
	return env
}

// removeProotSession removes the session directory, unless a filesystem is
// still mounted under it: removing it would then also remove the content of
// that filesystem, like a persistent overlay.
func removeProotSession(path string) {
	entries, err := proc.GetMountInfoEntry("/proc/self/mountinfo")
	if err != nil {
		sylog.Warningf("Not removing %s: %s", path, err)
		return
	}
	for _, entry := range entries {
		if isUnder(entry.Point, path) {
			sylog.Warningf("Not removing %s: %s is still mounted", path, entry.Point)
			return
		}
	}
	if err := types.FixPerms(path); err != nil {
		sylog.Debugf("FixPerms had a problem: %v", err)
	}
	if err := os.RemoveAll(path); err != nil {
		sylog.Warningf("While removing %s: %s", path, err)
	}
}

// prootUmount unmounts the FUSE filesystems that the image driver mounted
// in the host mount namespace, then waits for the driver processes.
func prootUmount() error {
	// empty target to signify to driver we are entering in the stop phase
	imageDriver.Stop("")

	entries, err := proc.GetMountInfoEntry("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	mounted := make(map[string]bool)
	for _, entry := range entries {
		mounted[entry.Point] = true
	}

	var errs []string
	for i := len(umountPoints) - 1; i >= 0; i-- {
		p := umountPoints[i].path
		if !mounted[p] {
			continue
		}
		if umountPoints[i].writable {
			if fd, err := unix.Open(p, unix.O_DIRECTORY, 0); err == nil {
				if err := unix.Syncfs(fd); err != nil {
					sylog.Debugf("Error syncing %s: %s", p, err)
				}
				unix.Close(fd)
			}
		}
		fusermount, err := prootutil.Fusermount()
		if err != nil {
			return err
		}
		sylog.Debugf("Umount %s", p)
		if out, err := exec.Command(fusermount, "-u", p).CombinedOutput(); err != nil {
			sylog.Debugf("%s -u %s failed, doing lazy umount: %s", fusermount, p, out)
			if out, err := exec.Command(fusermount, "-u", "-z", p).CombinedOutput(); err != nil {
				errs = append(errs, fmt.Sprintf("while unmounting %s: %s", p, out))
			}
		}
		if err := imageDriver.Stop(p); err != nil {
			errs = append(errs, fmt.Sprintf("while stopping driver for %s: %s", p, err))
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, ", "))
	}
	return nil
}
