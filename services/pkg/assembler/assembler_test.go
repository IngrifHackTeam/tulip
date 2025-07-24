// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"context"
	"testing"
	"tulip/pkg/db"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
)

type NoopDb struct{}

func (n *NoopDb) ConfigureDatabase() error                                { return nil }
func (n *NoopDb) GetTagList() ([]string, error)                           { return nil, nil }
func (n *NoopDb) GetSignature(string) (db.SuricataSig, error)             { return db.SuricataSig{}, nil }
func (n *NoopDb) SetStar(string, bool) error                              { return nil }
func (n *NoopDb) GetFlowDetail(string) (*db.FlowEntry, error)             { return nil, nil }
func (n *NoopDb) GetPcap(string) (bool, db.PcapFile)                      { return false, db.PcapFile{} }
func (n *NoopDb) InsertPcap(db.PcapFile) error                            { return nil }
func (n *NoopDb) GetFlagIds(int) ([]db.FlagId, error)                     { return nil, nil }
func (n *NoopDb) CountFlows(bson.D) (int64, error)                        { return 0, nil }
func (n *NoopDb) AddSignatureToFlow(db.FlowID, db.SuricataSig, int) error { return nil }
func (n *NoopDb) GetFingerprints(ctx context.Context) ([]int, error)      { return nil, nil }
func (n *NoopDb) InsertTags(tags []string) error                          { return nil }
func (n *NoopDb) InsertFlows(context.Context, []db.FlowEntry) error       { return nil }
func (n *NoopDb) GetFlows(context.Context, *db.FindFlowsOptions) ([]db.FlowEntry, error) {
	return nil, nil
}
func (n *NoopDb) AddTagsToFlow(db.FlowID, []string, int) error { return nil }

func makeTestAssembler(t *testing.T) *Service {
	t.Helper()
	cfg := Config{
		DB:                   &NoopDb{},
		TcpLazy:              false,
		Experimental:         false,
		NonStrict:            false,
		FlagRegex:            nil,
		ConnectionTcpTimeout: 0,
		ConnectionUdpTimeout: 0,
	}
	return NewAssemblerService(t.Context(), cfg)
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
