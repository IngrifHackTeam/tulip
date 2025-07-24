// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package collections

import "slices"

// AppendUnique appends an item to a slice if it is not already present.
func AppendUnique(slice []string, item ...string) []string {
	for _, v := range item {
		if !slices.Contains(slice, v) {
			slice = append(slice, v)
		}
	}
	return slice
}
