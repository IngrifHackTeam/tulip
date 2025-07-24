// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package analysis

import "tulip/pkg/db"

// AnalysisPass defines an interface for a "pass" in the analysis pipeline.
//
// A pass (taken from compiler terminology) is a single step in the analysis pipeline.
// Each pass takes a flow entry as input and performs some analysis steps on it,
// potentially modifying the flow entry or producing additional data.
//
// The order of passes is significant, as each pass may depend or interact with the
// results of previous passes. A pass could for example create some data that
// is then analyzed by a subsequent pass.
type AnalysisPass interface {
	Analyze(flow *db.FlowEntry) error
}
