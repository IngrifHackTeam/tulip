// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
	"tulip/pkg/db"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
)

// Helper to create a minimal valid classic PCAP file in memory
func makeValidPcap() []byte {
	buf := &bytes.Buffer{}
	w := pcapgo.NewWriter(buf)
	_ = w.WriteFileHeader(65535, 1) // Ethernet
	// Write a dummy packet
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(data),
		Length:        len(data),
	}
	_ = w.WritePacket(ci, data)
	return buf.Bytes()
}

// Helper to create a minimal PCAPNG file in memory (just the magic number)
func makeMinimalPcapng() []byte {
	// PCAPNG magic number: 0x0A0D0D0A
	return []byte{0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0}
}

// Helper to create a corrupted file (random bytes)
func makeCorruptedPcap() []byte {
	return []byte{0x01, 0x02, 0x03, 0x04, 0x05}
}

func writeTempFile(t *testing.T, data []byte, suffix string) string {
	t.Helper()
	tmpDir := t.TempDir()
	fname := filepath.Join(tmpDir, "testfile"+suffix)
	if err := os.WriteFile(fname, data, 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return fname
}

type NoopDatabase struct{}

func (n *NoopDatabase) GetFlowList(bson.D) ([]db.FlowEntry, error)     { return nil, nil }
func (n *NoopDatabase) GetTagList() ([]string, error)                  { return nil, nil }
func (n *NoopDatabase) GetSignature(string) (db.Signature, error)      { return db.Signature{}, nil }
func (n *NoopDatabase) SetStar(string, bool) error                     { return nil }
func (n *NoopDatabase) GetFlowDetail(id string) (*db.FlowEntry, error) { return nil, nil }
func (n *NoopDatabase) InsertFlows(ctx context.Context, flows []db.FlowEntry) error {
	return nil
}
func (n *NoopDatabase) GetPcap(string) (bool, db.PcapFile)    { return false, db.PcapFile{} }
func (n *NoopDatabase) InsertPcap(db.PcapFile) bool           { return true }
func (n *NoopDatabase) GetFlagIds() ([]db.FlagIdEntry, error) { return nil, nil }

func makeTestAssembler() *Service {
	cfg := Config{
		DB:                   &NoopDatabase{},
		TcpLazy:              false,
		Experimental:         false,
		NonStrict:            false,
		FlagRegex:            nil,
		FlushInterval:        0,
		ConnectionTcpTimeout: 0,
		ConnectionUdpTimeout: 0,
	}
	return NewAssemblerService(cfg)
}

func TestHandlePcapUri_DoesNotCrashOnCorruptedOrPcapng(t *testing.T) {
	assembler := makeTestAssembler()

	tests := []struct {
		name    string
		content []byte
	}{
		{"valid_pcap", makeValidPcap()},
		{"minimal_pcapng", makeMinimalPcapng()},
		{"corrupted", makeCorruptedPcap()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fname := writeTempFile(t, tc.content, "."+tc.name)
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("HandlePcapUri panicked on %s: %v", tc.name, r)
				}
			}()
			assembler.ProcessPcapPath(t.Context(), fname)
		})
	}
}

func TestApplyFlagRegexTags(t *testing.T) {

	makeFlowEntry := func(data ...string) *db.FlowEntry {
		flowItems := make([]db.FlowItem, len(data))
		nextFrom := "c"
		for i, d := range data {
			flowItems[i] = db.FlowItem{Raw: []byte(d), From: nextFrom}
			if nextFrom == "s" {
				nextFrom = "c"
			} else {
				nextFrom = "s"
			}
		}

		return &db.FlowEntry{Flow: flowItems, Tags: []string{}, Flags: []string{}}
	}

	cases := []struct {
		name          string
		input         *db.FlowEntry
		regex         string
		expectedTags  []string
		expectedFlags []string
	}{
		{
			"no match",
			makeFlowEntry("banana", "cherry"),
			"[a-z]{10}=",
			[]string{},
			[]string{},
		},
		{
			"single match flag-in",
			makeFlowEntry("FLAG{test}", "OK"),
			"FLAG\\{.*?\\}",
			[]string{"flag-in"},
			[]string{"FLAG{test}"},
		},
		{
			"single match flag-out",
			makeFlowEntry("asking for the flag", "FLAG{test}"),
			"FLAG\\{.*?\\}",
			[]string{"flag-out"},
			[]string{"FLAG{test}"},
		},
		{
			"empty input",
			makeFlowEntry(),
			"a.*",
			[]string{},
			[]string{},
		},
		{
			"real world scenario",
			makeFlowEntry(
				"FLAG{1234}",
				mustDecodeBase64(t, `SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IG5naW54LzEuMjcuNQ0KRGF0ZTogRnJpLCAyMCBKdW4gMjAyNSAxNTo1NjowNyBHTVQNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvbg0KQ29ubmVjdGlvbjogY2xvc2UNCg0KeyJpbnZpdGVzIjogW3siaWQiOiAiMDE5NzhlMDUtY2JkYi03ZDBjLWEwMzMtMzk5OTFhZDVjNGE2IiwgImZyb20iOiAiU2laUkJaVHd6MDcwIiwgInRpdGxlIjogImt2aHQzSHJIRm8iLCAiZGVzY3JpcHRpb24iOiAiNU8wODAxVkJJQUNMU1JQWjZONktVTVA5VlJIMDdBRT0iLCAiZGF0ZSI6ICIyMDMzLTA3LTE1In1dLCAic3VjY2VzcyI6IHRydWV9Cg==`)),
			"[A-Z0-9]{31}=",
			[]string{"flag-out"},
			[]string{"5O0801VBIACLSRPZ6N6KUMP9VRH07AE="},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg := regexp.MustCompile(c.regex)
			applyFlagRegexTags(c.input, reg)

			assert.Equal(t, c.expectedTags, c.input.Tags, "tags should match expected")
			assert.Equal(t, c.expectedFlags, c.input.Flags, "flags should match expected")
		})
	}
}

func mustDecodeBase64(t *testing.T, s string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	return string(decoded)
}

func makeFlowEntry(t *testing.T, raws ...[]byte) *db.FlowEntry {
	t.Helper()
	items := make([]db.FlowItem, len(raws))
	for i, raw := range raws {
		items[i] = db.FlowItem{Raw: raw}
	}
	return &db.FlowEntry{Flow: items}
}

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
			sanitizeFlowItemData(flow)

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
