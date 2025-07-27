// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package ingestor

import (
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"valid_filename", "valid_filename"},
		{"invalid:filename", "invalid_filename"},
		{"another/invalid\\filename", "another_invalid_filename"},
		{"", ""},
		{"no_special_chars", "no_special_chars"},
		{"123:456/789\\0", "123_456_789_0"},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			result := sanitizeFilename(c.input)
			if result != c.expected {
				t.Errorf("sanitizeFilename(%q) = %q; want %q", c.input, result, c.expected)
			}
		})
	}
}
