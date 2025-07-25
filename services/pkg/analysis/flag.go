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
	"regexp"
	"tulip/pkg/collections"
	"tulip/pkg/db"
)

const (
	tagFlagIn  = "flag-in"  // Tag for flags coming from the client
	tagFlagOut = "flag-out" // Tag for flags coming from the server
)

type flagPass struct {
	r *regexp.Regexp // Regular expression to match flags
}

// FlagAnalyzer creates a new flag analyzer pass.
// The regular expression is used to match flags in the FlowEntry items,
// in particular in each .Raw field of the .Flow slice.
func FlagAnalyzer(r *regexp.Regexp) Pass {
	return &flagPass{r: r}
}

func (a *flagPass) String() string { return "Flag Analyzer" }

// Run implements the Analyzer interface for flagAnalyzer.
func (a *flagPass) Run(entry *db.FlowEntry) error {

	// for each flow item in the entry, search for flags using the regex
	for idx := 0; idx < len(entry.Flow); idx++ {
		flags, tags := searchForFlagsInItem(&entry.Flow[idx], a.r)

		entry.Tags = collections.AppendUnique(entry.Tags, tags...)
		entry.Flags = collections.AppendUnique(entry.Flags, flags...)
	}

	return nil
}

// searchForFlagsInItem returns flags and associated tags found in a flow item
// using the provided regex. It returns empty slices if no flags are found.
func searchForFlagsInItem(
	item *db.FlowItem,
	flagRegex *regexp.Regexp,
) (flags []string, tags []string) {
	matches := flagRegex.FindAllSubmatch(item.Raw, -1)
	if len(matches) == 0 {
		return // No matches found, skip further processing
	}

	// add the relevant tag
	switch item.From {
	case db.FlowItemFromServer:
		tags = collections.AppendUnique(tags, tagFlagOut)
	case db.FlowItemFromClient:
		tags = collections.AppendUnique(tags, tagFlagIn)
	}

	// Add the flags
	for _, match := range matches {
		flag := string(match[0])
		flags = collections.AppendUnique(flags, flag)
	}
	return
}
