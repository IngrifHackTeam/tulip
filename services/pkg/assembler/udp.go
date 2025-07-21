// SPDX-FileCopyrightText: 2022 Qyn <qyn-ctf@gmail.com>
// SPDX-FileCopyrightText: 2023 liskaant <liskaant@gmail.com>
// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"time"
	"tulip/pkg/db"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// UdpStreamId uniquely identifies a bidirectional UDP stream
// based on the endpoints and ports involved in the communication.
type UdpStreamId struct {
	EndpointLower uint64
	EndpointUpper uint64
	PortLower     uint16
	PortUpper     uint16
}

// NewUdpStreamId generates a unique identifier for a UDP stream based on its endpoints and ports.
// The arguments can be in any order, and the function ensures that the identifiers are always ordered
// such that EndpointLower < EndpointUpper and PortLower < PortUpper.
func NewUdpStreamId(e1, e2 gopacket.Endpoint, p1, p2 layers.UDPPort) UdpStreamId {
	h1, h2 := e1.FastHash(), e2.FastHash()

	pn1, pn2 := uint16(p1), uint16(p2)

	id := UdpStreamId{}

	if h1 > h2 {
		id.EndpointLower = h2
		id.EndpointUpper = h1
	} else {
		id.EndpointLower = h1
		id.EndpointUpper = h2
	}

	if pn1 > pn2 {
		id.PortLower = pn2
		id.PortUpper = pn1
	} else {
		id.PortLower = pn1
		id.PortUpper = pn2
	}
	return id
}

// UDPAssembler is responsible for assembling UDP streams from packets.
//
// It tries to adhere to the same interface as TCPAssembler, allowing it to be used in a similar way.
// It maintains a map of active UDP streams, identified by their endpoints and ports.
type UDPAssembler struct {
	streams map[UdpStreamId]*UdpStream
}

func NewUDPAssembler() *UDPAssembler {
	return &UDPAssembler{
		streams: map[UdpStreamId]*UdpStream{},
	}
}

func (a *UDPAssembler) getOrCreateUdpStream(id UdpStreamId) *UdpStream {
	// get or create the stream
	stream, ok := a.streams[id]
	if !ok {
		stream = &UdpStream{Items: make([]db.FlowItem, 0)}
		a.streams[id] = stream
	}
	return stream
}

func (a *UDPAssembler) AssembleWithContext(
	netFlow gopacket.Flow,
	u *layers.UDP,
	ac reassembly.AssemblerContext,
) *UdpStream {
	// cast to our context type
	context, ok := ac.(Context)
	if !ok {
		panic("TcpStreamFactory: AssemblerContext is not of type *assembler.Context")
	}

	id := NewUdpStreamId(netFlow.Src(), netFlow.Dst(), u.SrcPort, u.DstPort)

	// get or create the stream
	stream := a.getOrCreateUdpStream(id)

	stream.processSegment(netFlow, u, context)
	return stream
}

func (a *UDPAssembler) CompleteOlderThan(threshold time.Time) []*db.FlowEntry {
	completeFlows := make([]*db.FlowEntry, 0)

	for id, stream := range a.streams {
		if stream.LastSeen.Unix() < threshold.Unix() {
			completeFlows = append(completeFlows, completeReassembly(stream))
			delete(a.streams, id) // remove from active streams
		}
	}

	return completeFlows
}

func completeReassembly(stream *UdpStream) *db.FlowEntry {
	if len(stream.Items) == 0 {
		return nil // No items in the stream, nothing to return
	}

	firstPkt := stream.Items[0]
	lastPkt := stream.Items[len(stream.Items)-1]

	startTime := firstPkt.Time
	duration := lastPkt.Time - startTime

	return &db.FlowEntry{
		SrcIp:        stream.netSrc.String(),
		DstIp:        stream.netDst.String(),
		SrcPort:      int(stream.portSrc),
		DstPort:      int(stream.portDst),
		Time:         startTime,
		Duration:     duration,
		Num_packets:  int(stream.PacketCount),
		Blocked:      false,
		Tags:         []string{"udp"},
		Suricata:     []string{},
		Filename:     stream.Source,
		Flow:         stream.Items,
		Flags:        []string{},
		Flagids:      []string{},
		Fingerprints: []uint32{},
		Size:         int(stream.PacketSize),
	}
}

// UdpStream represents a sequence of UDP packets between two endpoints,
// identified by their endpoints and ports.
type UdpStream struct {
	netSrc  gopacket.Endpoint // Network layer source endpoint (IP) of the first packet in the stream
	netDst  gopacket.Endpoint // Network layer destination endpoint (IP) of the first packet in the stream
	portSrc layers.UDPPort    // Source port of the UDP stream
	portDst layers.UDPPort    // Destination port of the UDP stream

	PacketCount uint      // Number of packets in the stream
	PacketSize  uint      // Total size of the packets in the stream
	Source      string    // Source of the stream, e.g., filename or network interface
	LastSeen    time.Time // Timestamp of the last packet seen in the stream

	Items []db.FlowItem // Items in the stream, containing payload and metadata
}

func (stream *UdpStream) Id() UdpStreamId {
	return NewUdpStreamId(stream.netSrc, stream.netDst, stream.portSrc, stream.portDst)
}

func (stream *UdpStream) processSegment(
	flow gopacket.Flow,
	udp *layers.UDP,
	captureInfo Context,
) {
	if len(udp.Payload) == 0 {
		return // skip empty segments
	}

	from := "s"
	if flow.Dst().FastHash() == stream.netSrc.FastHash() {
		from = "c"
	}

	stream.LastSeen = captureInfo.Timestamp
	stream.PacketCount += 1
	stream.PacketSize += uint(len(udp.Payload))

	// We have to make sure to stay under the document limit
	available := uint(streamdoc_limit) - stream.PacketSize

	length := uint(len(udp.Payload))

	// clamp length to [0, available]
	length = min(length, available)
	length = max(length, 0)

	stream.Items = append(stream.Items, db.FlowItem{
		From: from,
		Data: string(udp.Payload[:length]),
		Time: int(captureInfo.Timestamp.UnixNano() / 1000000), // TODO; maybe use int64?
	})
}
