// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package collections

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAppendUnique(t *testing.T) {
	cases := []struct {
		name     string
		input    []string
		item     string
		expected []string
	}{
		{"append new item", []string{"a", "b", "c"}, "d", []string{"a", "b", "c", "d"}},
		{"append duplicate item", []string{"a", "b", "c"}, "b", []string{"a", "b", "c"}},
		{"append to empty slice", []string{}, "x", []string{"x"}},
		{"append duplicate single", []string{"x"}, "x", []string{"x"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := AppendUnique(c.input, c.item)
			assert.Equal(t, len(c.expected), len(result), "length mismatch")
			for i, v := range c.expected {
				assert.Equal(t, v, result[i], "at index %d", i)
			}
		})
	}
}

func BenchmarkAppendUnique(b *testing.B) {
	slice := make([]string, 0, 1000)
	for i := range 1000 {
		if i%10 == 0 {
			slice = append(slice, "dup")
		} else {
			slice = append(slice, string(rune('a'+(i%26))))
		}
	}

	// Prepare a set of items to append, some duplicates, some new
	items := []string{"dup", "z", "a", "new1", "new2", "b", "dup", "new3"}

	for i := 0; b.Loop(); i++ {
		// Cycle through items to append
		item := items[i%len(items)]
		_ = AppendUnique(slice, item)
	}
}
