// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

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
			result := appendUnique(c.input, c.item)
			assert.Equal(t, len(c.expected), len(result), "length mismatch")
			for i, v := range c.expected {
				assert.Equal(t, v, result[i], "at index %d", i)
			}
		})
	}
}
