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
	"strings"
	"tulip/pkg/db"
)

type humanizerPass struct{}

// Humanizer creates a new humanizer pass.
// This pass populates the .Data field of FlowEntry items
// with a human-readable representation of the .Raw field.
//
// It works by replacing every character that is not a printable
// ASCII character with a dot ('.'), similar to the `hexdump` command.
func Humanizer() Pass {
	return &humanizerPass{}
}

func (a *humanizerPass) String() string { return "Humanizer" }

// Run implements the Analyzer interface for humanizerPass.
func (a *humanizerPass) Run(flow *db.FlowEntry) error {
	for idx := range flow.Flow {
		flowItem := &flow.Flow[idx]
		flowItem.Data = sanitizeRawData(flowItem.Raw)
	}

	return nil
}

// sanitizeRawData filters the raw byte slice to only include printable characters,
// replacing non-printable characters with '.'.
func sanitizeRawData(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))

	// Filter the data string down to only printable characters
	for _, c := range raw {
		if (c >= 32 && c <= 126) || c == '\t' || c == '\r' || c == '\n' {
			b.WriteByte(c)
		} else {
			b.WriteByte('.') // Replace non-printable characters with '.'
		}
	}
	return b.String()
}
