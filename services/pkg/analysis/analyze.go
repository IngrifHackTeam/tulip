// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package analysis

import (
	"fmt"
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
