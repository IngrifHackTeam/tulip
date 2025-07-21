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
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
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

func makeTestAssembler(t *testing.T) *Service {
	t.Helper()
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
	return NewAssemblerService(t.Context(), cfg)
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
func TestDefragPacket_NoIPv4Layer_ReturnsComplete(t *testing.T) {
	assembler := makeTestAssembler(t)

	// Create a packet with no IPv4 layer
	packet := gopacket.NewPacket([]byte{0x00, 0x01, 0x02}, gopacket.DecodePayload, gopacket.Default)

	complete, _ := assembler.defragPacket(packet)

	assert.True(t, complete, "should be complete if no IPv4 layer")
}

type fakeDefragmenter struct {
	defragIPv4Func func(ip4 *layers.IPv4) (*layers.IPv4, error)
}

func (f *fakeDefragmenter) DefragIPv4(ip4 *layers.IPv4) (*layers.IPv4, error) {
	return f.defragIPv4Func(ip4)
}

func makeIPv4Packet(payload []byte, fragOffset uint16, moreFragments bool, totalLen uint16) gopacket.Packet {
	ip4 := &layers.IPv4{
		Version:    4,
		IHL:        5,
		Length:     totalLen,
		Id:         1234,
		Flags:      layers.IPv4MoreFragments,
		FragOffset: fragOffset,
		Protocol:   layers.IPProtocolTCP,
		SrcIP:      []byte{1, 2, 3, 4},
		DstIP:      []byte{5, 6, 7, 8},
	}
	if !moreFragments {
		ip4.Flags = 0
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	_ = ip4.SerializeTo(buf, opts)
	serialized := buf.Bytes()
	// Append payload manually
	serialized = append(serialized, payload...)
	packet := gopacket.NewPacket(serialized, layers.LayerTypeIPv4, gopacket.Default)
	return packet
}
func TestDefragPacket_FragmentedPacket(t *testing.T) {
	assembler := makeTestAssembler(t)

	// Fragment 1: offset 0, more fragments flag set
	frag1Payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	ip4frag1 := &layers.IPv4{
		Version:    4,
		IHL:        5,
		Length:     20 + uint16(len(frag1Payload)),
		Id:         1234,
		Flags:      layers.IPv4MoreFragments,
		FragOffset: 0,
		Protocol:   layers.IPProtocolTCP,
		SrcIP:      []byte{1, 2, 3, 4},
		DstIP:      []byte{5, 6, 7, 8},
	}
	buf1 := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	_ = ip4frag1.SerializeTo(buf1, opts)
	serialized1 := buf1.Bytes()
	serialized1 = append(serialized1, frag1Payload...)
	packet1 := gopacket.NewPacket(serialized1, layers.LayerTypeIPv4, gopacket.Default)

	// Fragment 2: offset 1 (8 bytes / 8 = 1), more fragments flag not set
	frag2Payload := []byte{0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	ip4frag2 := &layers.IPv4{
		Version:    4,
		IHL:        5,
		Length:     20 + uint16(len(frag2Payload)),
		Id:         1234,
		Flags:      0, // Last fragment
		FragOffset: 1, // Offset in 8-byte units
		Protocol:   layers.IPProtocolTCP,
		SrcIP:      []byte{1, 2, 3, 4},
		DstIP:      []byte{5, 6, 7, 8},
	}
	buf2 := gopacket.NewSerializeBuffer()
	_ = ip4frag2.SerializeTo(buf2, opts)
	serialized2 := buf2.Bytes()
	serialized2 = append(serialized2, frag2Payload...)
	packet2 := gopacket.NewPacket(serialized2, layers.LayerTypeIPv4, gopacket.Default)

	assembler.defragmenter = ip4defrag.NewIPv4Defragmenter()

	complete, err := assembler.defragPacket(packet1)
	assert.False(t, complete, "should not be complete if fragment not reassembled")
	// Do not assert NoError, as incomplete fragments may return an error

	complete, err = assembler.defragPacket(packet2)
	assert.True(t, complete, "should be complete if fragment reassembled")
	assert.NoError(t, err)
}

func TestDefragPacket_DefragError_ReturnsError(t *testing.T) {
	assembler := makeTestAssembler(t)
	// Create a fragment with invalid length to trigger a defrag error
	ip4 := &layers.IPv4{
		Version:    4,
		IHL:        5,
		Length:     20, // too small for a valid fragment
		Id:         1234,
		Flags:      layers.IPv4MoreFragments,
		FragOffset: 0,
		Protocol:   layers.IPProtocolTCP,
		SrcIP:      []byte{1, 2, 3, 4},
		DstIP:      []byte{5, 6, 7, 8},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	_ = ip4.SerializeTo(buf, opts)
	serialized := buf.Bytes()
	serialized = append(serialized, []byte{0xde, 0xad}...)
	packet := gopacket.NewPacket(serialized, layers.LayerTypeIPv4, gopacket.Default)

	assembler.defragmenter = ip4defrag.NewIPv4Defragmenter()

	complete, err := assembler.defragPacket(packet)
	assert.False(t, complete, "should not be complete if defrag error")
	assert.Error(t, err, "should return an error for invalid fragment")
}

type fakePacketBuilder struct {
	nextLayerDecoded bool
}

func (f *fakePacketBuilder) AddLayer(gopacket.Layer)       {}
func (f *fakePacketBuilder) NextDecoder() gopacket.Decoder { return nil }
func (f *fakePacketBuilder) DecodeLayerPayload(gopacket.Decoder, []byte) error {
	f.nextLayerDecoded = true
	return nil
}

type fakeDecoder struct{ called bool }

func (f *fakeDecoder) Decode([]byte, gopacket.PacketBuilder) error {
	f.called = true
	return nil
}

func TestDefragPacket_CompletePacket_DecodesNextLayer(t *testing.T) {
	assembler := makeTestAssembler(t)
	payload := []byte{0xde, 0xad, 0xbe, 0xef}

	ip4 := &layers.IPv4{
		Version:    4,
		IHL:        5,
		Length:     20 + 20 + uint16(len(payload)), // IPv4 header + TCP header + payload
		Id:         1234,
		Flags:      0, // Not fragmented
		FragOffset: 0,
		Protocol:   layers.IPProtocolTCP,
		SrcIP:      []byte{1, 2, 3, 4},
		DstIP:      []byte{5, 6, 7, 8},
	}
	tcp := &layers.TCP{
		SrcPort: 1234,
		DstPort: 80,
		Seq:     1,
	}
	tcp.SetNetworkLayerForChecksum(ip4)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, ip4, tcp, gopacket.Payload(payload))
	assert.NoError(t, err)
	serialized := buf.Bytes()

	packet := gopacket.NewPacket(serialized, layers.LayerTypeIPv4, gopacket.Default)
	assembler.defragmenter = ip4defrag.NewIPv4Defragmenter()

	complete, err := assembler.defragPacket(packet)
	assert.True(t, complete, "should be complete after defrag")
	assert.NoError(t, err)

	// Check that TCP layer is present
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	assert.NotNil(t, tcpLayer, "TCP layer should be decoded after IPv4 defrag")
}
