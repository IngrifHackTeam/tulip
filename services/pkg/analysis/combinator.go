// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package analysis

import (
	"strings"
	"tulip/pkg/db"
)

// Sequence represents a sequence of analysis passes to be executed in order.
//
// Sequence is a pass itself, allowing it to be combined with other passes.
type Sequence struct {
	passes []Pass // The ordered list of passes to execute in the pipeline.
}

func NewSequence(passes ...Pass) Pass {
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

// Parallel represents a parallel execution of multiple analysis passes.
//
// Parallel is a pass itself, allowing it to be combined with other passes.
type Parallel struct {
	passes []Pass // The list of passes to execute in parallel.
}

func NewParallel(passes ...Pass) Pass {
	return &Parallel{passes: passes}
}

func (p *Parallel) String() string {
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
