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
)

// UDPAssembler is responsible for assembling UDP streams from packets.
type UDPAssembler struct {
	streams map[UdpStreamIdendifier]*UdpStream
}

func NewUDPAssembler() *UDPAssembler {
	return &UDPAssembler{
		streams: map[UdpStreamIdendifier]*UdpStream{},
	}
}

func (a *UDPAssembler) Assemble(
	flow gopacket.Flow,
	udp *layers.UDP,
	captureInfo *gopacket.CaptureInfo,
	source string,
) *UdpStream {
	id := flowToUdpStreamId(flow, udp)

	// get or create the stream
	stream, ok := a.streams[id]
	if !ok {
		stream = &UdpStream{
			Identifier: id,
			Flow:       flow,
			PortSrc:    udp.SrcPort,
			PortDst:    udp.DstPort,
			Source:     source,
		}

		a.streams[id] = stream
	}

	stream.processSegment(flow, udp, captureInfo)
	return stream
}

func flowToUdpStreamId(flow gopacket.Flow, udp *layers.UDP) UdpStreamIdendifier {
	endpointSrc := flow.Src().FastHash()
	endpointDst := flow.Dst().FastHash()
	portSrc := uint16(udp.SrcPort)
	portDst := uint16(udp.DstPort)
	id := UdpStreamIdendifier{}

	if endpointSrc > endpointDst {
		id.EndpointLower = endpointDst
		id.EndpointUpper = endpointSrc
	} else {
		id.EndpointLower = endpointSrc
		id.EndpointUpper = endpointDst
	}

	if portSrc > portDst {
		id.PortLower = portDst
		id.PortUpper = portSrc
	} else {
		id.PortLower = portSrc
		id.PortUpper = portDst
	}
	return id
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

	src, dst := stream.Flow.Endpoints()

	return &db.FlowEntry{
		SrcPort:      int(stream.PortSrc),
		DstPort:      int(stream.PortDst),
		SrcIp:        src.String(),
		DstIp:        dst.String(),
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

type UdpStreamIdendifier struct {
	EndpointLower uint64
	EndpointUpper uint64
	PortLower     uint16
	PortUpper     uint16
}

type UdpStream struct {
	Identifier  UdpStreamIdendifier
	Flow        gopacket.Flow
	PacketCount uint
	PacketSize  uint
	Items       []db.FlowItem
	PortSrc     layers.UDPPort
	PortDst     layers.UDPPort
	Source      string
	LastSeen    time.Time
}

func (stream *UdpStream) processSegment(flow gopacket.Flow, udp *layers.UDP, captureInfo *gopacket.CaptureInfo) {
	if len(udp.Payload) == 0 {
		return
	}

	from := "s"
	if flow.Dst().FastHash() == stream.Flow.Src().FastHash() {
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
