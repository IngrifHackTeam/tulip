// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package analysis

import (
	"errors"
	"testing"
	"tulip/pkg/db"

	"github.com/stretchr/testify/assert"
)

type mockPass struct {
	name      string
	shouldErr bool
	called    *bool
}

func (m *mockPass) String() string {
	return m.name
}

func (m *mockPass) Run(flow *db.FlowEntry) error {
	if m.called != nil {
		*m.called = true
	}
	if m.shouldErr {
		return errors.New("mock error")
	}
	return nil
}

func TestSequence_Run(t *testing.T) {
	called1, called2 := false, false
	pass1 := &mockPass{name: "pass1", called: &called1}
	pass2 := &mockPass{name: "pass2", called: &called2}
	seq := NewSequence(pass1, pass2)
	flow := &db.FlowEntry{}

	err := seq.Run(flow)
	assert.NoError(t, err, "expected no error")
	assert.True(t, called1, "expected pass1 to be called")
	assert.True(t, called2, "expected pass2 to be called")
}

func TestSequence_Run_Error(t *testing.T) {
	pass1 := &mockPass{name: "pass1", shouldErr: true}
	pass2 := &mockPass{name: "pass2"}
	seq := NewSequence(pass1, pass2)
	flow := &db.FlowEntry{}

	err := seq.Run(flow)
	assert.Error(t, err, "expected error")
}

func TestSequence_String(t *testing.T) {
	pass1 := &mockPass{name: "A"}
	pass2 := &mockPass{name: "B"}
	seq := NewSequence(pass1, pass2)
	want := "Sequence(A, B)"
	got := seq.String()
	assert.Equal(t, want, got)
}

func TestSequence_AddPass(t *testing.T) {
	seq := NewSequence()
	pass := &mockPass{name: "added"}
	seq.AddPass(pass)
	got := seq.String()
	assert.Equal(t, "Sequence(added)", got)
}

func TestParallel_Run(t *testing.T) {
	called1, called2 := false, false
	pass1 := &mockPass{name: "p1", called: &called1}
	pass2 := &mockPass{name: "p2", called: &called2}
	par := NewParallel(pass1, pass2)
	flow := &db.FlowEntry{}

	err := par.Run(flow)
	assert.NoError(t, err, "expected no error")
	assert.True(t, called1, "expected pass1 to be called")
	assert.True(t, called2, "expected pass2 to be called")
}

func TestParallel_Run_Error(t *testing.T) {
	pass1 := &mockPass{name: "p1", shouldErr: true}
	pass2 := &mockPass{name: "p2"}
	par := NewParallel(pass1, pass2)
	flow := &db.FlowEntry{}

	err := par.Run(flow)
	assert.Error(t, err, "expected error")
}

func TestParallel_Name(t *testing.T) {
	pass1 := &mockPass{name: "X"}
	pass2 := &mockPass{name: "Y"}
	par := NewParallel(pass1, pass2)
	want := "Parallel(X, Y)"
	got := par.Name()
	assert.Equal(t, want, got)
}
