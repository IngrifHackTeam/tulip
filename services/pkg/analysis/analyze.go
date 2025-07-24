// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package analysis

import (
	"fmt"
	"strings"
	"tulip/pkg/db"
)

// Pass defines an interface for a "pass" in the analysis pipeline.
//
// A pass (taken from compiler terminology) is a single step in the analysis pipeline.
// Each pass takes a flow entry as input and performs some analysis steps on it,
// potentially modifying the flow entry or producing additional data.
//
// The order of passes is significant, as each pass may depend or interact with the
// results of previous passes. A pass could for example create some data that
// is then analyzed by a subsequent pass.
type Pass interface {
	fmt.Stringer
	// String returns the name of the pass, used for logging and debugging.
	String() string
	// Run performs the analysis on the given flow entry.
	Run(flow *db.FlowEntry) error
}

// Sequence represents a sequence of analysis passes to be executed in order.
//
// Sequence is a pass itself, allowing it to be combined with other passes.
type Sequence struct {
	passes []Pass // The ordered list of passes to execute in the pipeline.
}

func NewSequence(passes ...Pass) *Sequence {
	return &Sequence{passes: passes}
}

func (p *Sequence) String() string {
	var b strings.Builder
	b.WriteString("Sequence(")
	for i, pass := range p.passes {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(pass.String())
	}
	b.WriteString(")")
	return b.String()
}

func (p *Sequence) Run(flow *db.FlowEntry) error {
	for _, pass := range p.passes {
		if err := pass.Run(flow); err != nil {
			return err
		}
	}
	return nil
}

func (p *Sequence) AddPass(pass Pass) {
	p.passes = append(p.passes, pass)
}

// Parallel represents a parallel execution of multiple analysis passes.
//
// Parallel is a pass itself, allowing it to be combined with other passes.
type Parallel struct {
	passes []Pass // The list of passes to execute in parallel.
}

func NewParallel(passes ...Pass) *Parallel {
	return &Parallel{passes: passes}
}

func (p *Parallel) Name() string {
	var b strings.Builder
	b.WriteString("Parallel(")
	for i, pass := range p.passes {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(pass.String())
	}
	b.WriteString(")")
	return b.String()
}

func (p *Parallel) Run(flow *db.FlowEntry) error {
	// Execute each pass in parallel.
	errs := make(chan error, len(p.passes))
	for _, pass := range p.passes {
		go func(pass Pass) {
			errs <- pass.Run(flow)
		}(pass)
	}

	// Collect errors from all passes.
	for range p.passes {
		if err := <-errs; err != nil {
			return err
		}
	}
	return nil
}
