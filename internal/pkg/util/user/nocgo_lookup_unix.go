// Copyright (c) Contributors to the Apptainer project, established as
//   Apptainer a Series of LF Projects LLC.
//   For website terms of use, trademark policy, privacy policy and other
//   project policies see https://lfprojects.org/policies
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

//go:build (aix || darwin || dragonfly || freebsd || (!android && linux) || netbsd || openbsd || solaris) && (!cgo || osusergo)

package user

import (
	"bufio"
	"fmt"
	"os"
	osuser "os/user"
	"strconv"
	"strings"
	"syscall"
)

const (
	passwdFile = "/etc/passwd"
	groupFile  = "/etc/group"
)

// findEntry returns the colon separated fields of the first line in path
// with at least minFields fields for which match returns true.
func findEntry(path string, minFields int, match func([]string) bool) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= minFields && match(fields) {
			return fields, nil
		}
	}
	return nil, scanner.Err()
}

func buildUser(fields []string) (*User, error) {
	uid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(fields[3], 10, 32)
	if err != nil {
		return nil, err
	}
	return &User{
		Name:  fields[0],
		UID:   uint32(uid),
		GID:   uint32(gid),
		Gecos: fields[4],
		Dir:   fields[5],
		Shell: fields[6],
	}, nil
}

func buildGroup(fields []string) (*Group, error) {
	gid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return nil, err
	}
	return &Group{
		Name: fields[0],
		GID:  uint32(gid),
	}, nil
}

func current() (*User, error) {
	return lookupUnixUid(syscall.Getuid())
}

func lookupUser(username string) (*User, error) {
	fields, err := findEntry(passwdFile, 7, func(f []string) bool { return f[0] == username })
	if err != nil {
		return nil, fmt.Errorf("user: lookup username %s: %v", username, err)
	}
	if fields == nil {
		return nil, osuser.UnknownUserError(username)
	}
	return buildUser(fields)
}

// nolint
func lookupUnixUid(uid int) (*User, error) {
	id := strconv.Itoa(uid)
	fields, err := findEntry(passwdFile, 7, func(f []string) bool { return f[2] == id })
	if err != nil {
		return nil, fmt.Errorf("user: lookup userid %d: %v", uid, err)
	}
	if fields == nil {
		return nil, osuser.UnknownUserIdError(uid)
	}
	return buildUser(fields)
}

func currentGroup() (*Group, error) {
	return lookupUnixGid(syscall.Getgid())
}

func lookupGroup(groupname string) (*Group, error) {
	fields, err := findEntry(groupFile, 3, func(f []string) bool { return f[0] == groupname })
	if err != nil {
		return nil, fmt.Errorf("user: lookup groupname %s: %v", groupname, err)
	}
	if fields == nil {
		return nil, osuser.UnknownGroupError(groupname)
	}
	return buildGroup(fields)
}

// nolint
func lookupUnixGid(gid int) (*Group, error) {
	id := strconv.Itoa(gid)
	fields, err := findEntry(groupFile, 3, func(f []string) bool { return f[2] == id })
	if err != nil {
		return nil, fmt.Errorf("user: lookup groupid %d: %v", gid, err)
	}
	if fields == nil {
		return nil, osuser.UnknownGroupIdError(id)
	}
	return buildGroup(fields)
}
