// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package desktop

import (
	"cmp"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// integrityLevel is the mandatory integrity level of a process: 0x2000 for
// one a user starts, 0x3000 for one run as administrator. Windows drops
// input this process sends to a window of a higher level, though SendInput
// reports it sent, and refuses the window's element actions; reads of the
// window and screenshots of it still work.
type integrityLevel uint32

// integrityLevels reads integrity levels. ok is false when the system does
// not say, as for a process of another user.
type integrityLevels interface {
	// own reports the level of this process.
	own() (level integrityLevel, ok bool)
	// of reports the level of a process.
	of(pid uint32) (level integrityLevel, ok bool)
}

// systemLevels reads the levels from the processes' tokens.
var systemLevels integrityLevels = tokenLevels{}

type tokenLevels struct{}

// ownLevel is read once, since a process keeps the level it started at.
var ownLevel = sync.OnceValues(func() (integrityLevel, bool) {
	return tokenLevel(windows.GetCurrentProcessToken())
})

func (tokenLevels) own() (integrityLevel, bool) { return ownLevel() }

func (tokenLevels) of(pid uint32) (integrityLevel, bool) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, false
	}
	defer func() { _ = windows.CloseHandle(process) }()
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return 0, false
	}
	defer func() { _ = token.Close() }()
	return tokenLevel(token)
}

// tokenLevel reads the level from a token's integrity SID, whose last
// subauthority it is.
func tokenLevel(token windows.Token) (integrityLevel, bool) {
	var size uint32
	// The first call reports the size of the label and the SID after it.
	_ = windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 {
		return 0, false
	}
	buf := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], size, &size); err != nil {
		return 0, false
	}
	sid := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid //nolint:gosec // the call wrote a TOKEN_MANDATORY_LABEL
	n := sid.SubAuthorityCount()
	if n == 0 {
		return 0, false
	}
	return integrityLevel(sid.SubAuthority(uint32(n) - 1)), true
}

// errElevated is the error for input or an element action that Windows
// keeps from app, which runs at a higher integrity level than this process.
// It matches ErrRefused, since nothing reached the application.
func errElevated(app string) error {
	return refusal(fmt.Sprintf("%q runs elevated, at a higher integrity level than this process, so Windows blocks input to it; run %q without administrator rights, or run Dagu at the same level", app, app))
}

// admitProcess returns the error naming app when process pid runs at a
// higher integrity level than this process. It returns nil when either
// level is unknown, so input is then sent as it always was.
func admitProcess(levels integrityLevels, pid uint32, app string) error {
	own, ok := levels.own()
	if !ok {
		return nil
	}
	if level, ok := levels.of(pid); ok && level > own {
		return errElevated(app)
	}
	return nil
}

// admitInput returns the error naming w's application when Windows would
// drop input sent to w, and nil for a window it delivers to or one the
// system does not name.
func admitInput(levels integrityLevels, w WindowID) error {
	if !w.Known() {
		return nil
	}
	return admitProcess(levels, w.PID, cmp.Or(w.App, w.Title))
}
