// SPDX-FileCopyrightText: 2022 Rick de Jager <rickdejager99@gmail.com>
// SPDX-FileCopyrightText: 2022 erdnaxe <erdnaxe@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 - 2024 gfelber <34159565+gfelber@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 - 2025 Eyad Issa <eyadlorenzo@gmail.com>
// SPDX-FileCopyrightText: 2023 Max Groot <19346100+MaxGroot@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 Sijisu <mail@sijisu.eu>
// SPDX-FileCopyrightText: 2023 liskaant <50048810+liskaant@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 liskaant <liskaant@gmail.com>
// SPDX-FileCopyrightText: 2023 meme-lord <meme-lord@users.noreply.github.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package analysis

import (
	"fmt"
	"tulip/pkg/collections"
	"tulip/pkg/db"

	"github.com/flier/gohs/hyperscan"
)

const (
	tagFlagIn  = "flag-in"  // Tag for flags coming from the client
	tagFlagOut = "flag-out" // Tag for flags coming from the server
)

type flagPass struct {
	db      hyperscan.BlockDatabase
	scratch *hyperscan.Scratch
}

// FlagAnalyzer creates a new flag analyzer pass.
// The regular expression is used to match flags in the FlowEntry items,
// in particular in each .Raw field of the .Flow slice.
func FlagAnalyzer(expr string) (*flagPass, error) {
	pattern, err := hyperscan.ParsePattern(fmt.Sprintf("/%s/L", expr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse hyperscan pattern: %w", err)
	}

	db, err := hyperscan.NewManagedBlockDatabase(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to create hyperscan database: %w", err)
	}

	s, err := hyperscan.NewManagedScratch(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create hyperscan scratch: %w", err)
	}

	return &flagPass{
		db:      db,
		scratch: s,
	}, nil
}

func (a *flagPass) String() string { return "Flag Analyzer" }

// Run implements the Analyzer interface for flagAnalyzer.
func (a *flagPass) Run(entry *db.FlowEntry) error {

	flags := make([]string, 0)
	tags := make([]string, 0)

	for i := range entry.Flow {
		flowFlags, flowTags, err := a.runOnFlow(&entry.Flow[i])
		if err != nil {
			return fmt.Errorf("failed to run flag pass on flow: %w", err)
		}

		flags = collections.AppendUnique(flags, flowFlags...)
		tags = collections.AppendUnique(tags, flowTags...)
	}

	entry.Flags = collections.AppendUnique(entry.Flags, flags...)
	entry.Tags = collections.AppendUnique(entry.Tags, tags...)

	return nil
}

func (a *flagPass) runOnFlow(flow *db.FlowItem) (flags []string, tags []string, err error) {

	handler := hyperscan.MatchHandler(func(id uint, from, to uint64, matchFlags uint, context any) error {

		flag := string(flow.Raw[from:to])
		flags = collections.AppendUnique(flags, flag)

		switch flow.From {
		case db.FlowItemFromServer:
			tags = collections.AppendUnique(tags, tagFlagOut)
		case db.FlowItemFromClient:
			tags = collections.AppendUnique(tags, tagFlagIn)
		}

		return nil
	})

	// Scan the raw data with the handler
	if err := a.db.Scan(flow.Raw, a.scratch, handler, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to scan flow item with hyperscan: %w", err)
	}

	return
}
