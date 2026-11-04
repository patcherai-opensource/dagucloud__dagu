// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package desktop

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mandatory integrity levels a token can carry.
const (
	lowLevel    integrityLevel = 0x1000
	mediumLevel integrityLevel = 0x2000
	highLevel   integrityLevel = 0x3000
	systemLevel integrityLevel = 0x4000
)

// fakeLevels reports this process at self and others at their levels in
// procs; a process missing from procs is one the system does not say.
type fakeLevels struct {
	self  integrityLevel
	procs map[uint32]integrityLevel
}

func (f fakeLevels) own() (integrityLevel, bool) { return f.self, true }

func (f fakeLevels) of(pid uint32) (integrityLevel, bool) {
	level, ok := f.procs[pid]
	return level, ok
}

// Input to a window of an application above this process is refused with
// an error that names it and says how to fix it; a window at this level or
// below, or one whose level the system does not say, takes input.
func TestAdmitInput(t *testing.T) {
	t.Parallel()

	const higher, equal, lower, unknown = 1, 2, 3, 4
	levels := fakeLevels{self: mediumLevel, procs: map[uint32]integrityLevel{higher: highLevel, equal: mediumLevel, lower: lowLevel}}
	window := func(pid uint32) WindowID {
		return WindowID{Handle: 0x10, PID: pid, App: "notepad", Title: "Untitled - Notepad"}
	}

	err := admitInput(levels, window(higher))
	require.EqualError(t, err, `"notepad" runs elevated, at a higher integrity level than this process, so Windows blocks input to it; run "notepad" without administrator rights, or run Dagu at the same level`)
	assert.ErrorIs(t, err, ErrRefused, "nothing reached the application")

	for name, pid := range map[string]uint32{"equal": equal, "lower": lower, "unknown": unknown} {
		assert.NoError(t, admitInput(levels, window(pid)), name)
	}
	assert.NoError(t, admitInput(levels, WindowID{}), "a window the system does not name")
}

// The system reads this process's level the same from its own token as
// from its process, and its own windows take its input.
func TestTokenLevels(t *testing.T) {
	t.Parallel()

	pid := uint32(os.Getpid()) //nolint:gosec // a process id fits a DWORD
	own, ok := systemLevels.own()
	require.True(t, ok)
	assert.Contains(t, []integrityLevel{mediumLevel, highLevel, systemLevel}, own)
	level, ok := systemLevels.of(pid)
	require.True(t, ok)
	assert.Equal(t, own, level)
	assert.NoError(t, admitInput(systemLevels, WindowID{Handle: 0x10, PID: pid, App: "desktop.test"}))
}
