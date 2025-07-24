// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package analysis

import (
	"testing"
	"tulip/pkg/db"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeFlowItemData(t *testing.T) {

	tests := []struct {
		name     string
		input    [][]byte
		expected []string
	}{
		{
			name:     "all printable",
			input:    [][]byte{[]byte("Hello, World!"), []byte("12345")},
			expected: []string{"Hello, World!", "12345"},
		},
		{
			name:     "non-printable replaced",
			input:    [][]byte{[]byte{0x01, 0x02, 'A', 'B', 0x7F, 0x80, '\n', '\t'}},
			expected: []string{"..AB..\n\t"},
		},
		{
			name:     "mixed printable and non-printable",
			input:    [][]byte{[]byte("foo\x00bar"), []byte{0x10, 'X', 0x1B, 'Y'}},
			expected: []string{"foo.bar", ".X.Y"},
		},
		{
			name:     "empty input",
			input:    [][]byte{},
			expected: []string{},
		},
		{
			name:     "only non-printable",
			input:    [][]byte{[]byte{0x00, 0x01, 0x02}},
			expected: []string{"..."},
		},
		{
			name:     "printable with allowed whitespace",
			input:    [][]byte{[]byte("abc\tdef\nxyz\r")},
			expected: []string{"abc\tdef\nxyz\r"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			flow := makeFlowEntry(t, tc.input...)
			pass := Humanizer()
			err := pass.Analyze(flow)
			assert.NoError(t, err, "Analyze should not return an error")

			assert.Len(t, flow.Flow, len(tc.expected), "flow length mismatch")
			for i, expected := range tc.expected {
				assert.Less(t, i, len(flow.Flow), "index out of range for flow items")

				got := flow.Flow[i].Data
				assert.Equal(t, expected, got, "item %d: got %q, want %q", i, got, expected)
			}
		})
	}
}

func BenchmarkSanitizeRawData(b *testing.B) {
	b.ReportAllocs()
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 256) // Fill with all byte values
	}

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		sanitizeRawData(data)
	}
}

func makeFlowEntry(t *testing.T, raws ...[]byte) *db.FlowEntry {
	t.Helper()
	items := make([]db.FlowItem, len(raws))
	for i, raw := range raws {
		items[i] = db.FlowItem{Raw: raw}
	}
	return &db.FlowEntry{Flow: items}
}
