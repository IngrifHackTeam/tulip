// Originally based on code from Google's gopacket repository
// https://github.com/google/gopacket/blob/master/dumpcommand/tcpdump.go

// SPDX-FileCopyrightText: 2022 Qyn <qyn-ctf@gmail.com>
// SPDX-FileCopyrightText: 2022 Rick de Jager <rickdejager99@gmail.com>
// SPDX-FileCopyrightText: 2023 gfelber <34159565+gfelber@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 liskaant <liskaant@gmail.com>
// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"tulip/pkg/db"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

// TcpStreamFactory implements reassembly.StreamFactory for TCP streams.
type TcpStreamFactory struct {
	OnComplete     func(db.FlowEntry) // Callback to call when the stream is complete
	NonStrict      bool               // non-strict mode, used for testing
	StreamdocLimit int                // Limit for the size of the stream document in MongoDB
}

func (f *TcpStreamFactory) New(
	net, transport gopacket.Flow,
	tcp *layers.TCP,
	ac reassembly.AssemblerContext,
) reassembly.Stream {

	// cast to our context type
	context, ok := ac.(Context)
	if !ok {
		panic("TcpStreamFactory: AssemblerContext is not of type *assembler.Context")
	}

	fname := context.FileName

	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: f.NonStrict,
	}

	stream := &TcpStream{
		tcpFSM:         reassembly.NewTCPSimpleFSM(fsmOptions),
		tcpFSMErr:      false,
		streamdocLimit: f.StreamdocLimit,

		net:       net,
		transport: transport,

		optChecker: reassembly.NewTCPOptionCheck(),
		source:     fname,
		flowItems:  []db.FlowItem{},
		srcPort:    tcp.SrcPort,
		dstPort:    tcp.DstPort,
		onComplete: f.OnComplete,
		nonStrict:  f.NonStrict,
	}
	return stream
}

// TcpStream implements reassembly.Stream for TCP streams.
//
// assembly will, in order:
//  1. Create the stream via StreamFactory.New
//  2. Call ReassembledSG 0 or more times, passing in reassembled TCP data in order
//  3. Call ReassemblyComplete one time, after which the stream is dereferenced by assembly.
type TcpStream struct {
	streamdocLimit int // Limit for the size of the stream document in MongoDB

	tcpFSM    *reassembly.TCPSimpleFSM
	tcpFSMErr bool

	optChecker reassembly.TCPOptionCheck
	net        gopacket.Flow
	transport  gopacket.Flow

	// RDJ; These field are added to make mongo convertion easier
	source     string
	flowItems  []db.FlowItem
	srcPort    layers.TCPPort
	dstPort    layers.TCPPort
	totalSize  int
	numPackets int

	nonStrict bool // non-strict mode, used for testing

	onComplete func(db.FlowEntry) // Callback to call when the stream is complete
}

// Tell whether the TCP packet should be accepted, start could be
// modified to force a start even if no SYN have been seen
func (t *TcpStream) Accept(
	tcp *layers.TCP,
	ci gopacket.CaptureInfo,
	dir reassembly.TCPFlowDirection,
	nextSeq reassembly.Sequence,
	start *bool,
	ac reassembly.AssemblerContext,
) bool {
	// FSM
	if !t.tcpFSM.CheckState(tcp, dir) {
		if !t.tcpFSMErr {
			t.tcpFSMErr = true
		}

		if !t.nonStrict {
			return false
		}
	}

	// We just ignore the Checksum
	return true
}

// ReassembledSG is called zero or more times.
// ScatterGather is reused after each Reassembled call, so it's important to
// copy anything you need out of it, especially bytes (or use KeepFrom())
func (t *TcpStream) ReassembledSG(
	sg reassembly.ScatterGather,
	ac reassembly.AssemblerContext,
) {
	dir, _, _, _ := sg.Info()
	length, _ := sg.Lengths()
	capInfo := ac.GetCaptureInfo()
	timestamp := capInfo.Timestamp
	t.numPackets += 1

	// Don't add empty streams to the DB
	if length == 0 {
		return
	}

	data := sg.Fetch(length)

	// We have to make sure to stay under the document limit
	t.totalSize += length
	bytes_available := t.streamdocLimit - t.totalSize
	if length > bytes_available {
		length = bytes_available
	}
	if length < 0 {
		length = 0
	}

	var from db.FlowItemFrom
	if dir == reassembly.TCPDirClientToServer {
		from = db.FlowItemFromClient
	} else {
		from = db.FlowItemFromServer
	}

	// consolidate subsequent elements from the same origin
	l := len(t.flowItems)
	if l > 0 {
		if t.flowItems[l-1].From == from {
			t.flowItems[l-1].Raw = append(t.flowItems[l-1].Raw, data[:length]...)
			// All done, no need to add a new item
			return
		}
	}

	// Add a FlowItem based on the data we just reassembled
	t.flowItems = append(t.flowItems, db.FlowItem{
		Raw:  data[:length],
		From: from,
		Time: int(timestamp.UnixNano() / 1000000), // TODO; maybe use int64?
	})

}

// ReassemblyComplete is called when assembly decides there is
// no more data for this Stream, either because a FIN or RST packet
// was seen, or because the stream has timed out without any new
// packet data (due to a call to FlushCloseOlderThan).
// It should return true if the connection should be removed from the pool
// It can return false if it want to see subsequent packets with Accept(), e.g. to
// see FIN-ACK, for deeper state-machine analysis.
func (t *TcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {

	// Insert the stream into the mogodb.

	/*
		{
			"src_port": 32858,
			"dst_ip": "10.10.3.1",
			"contains_flag": false,
			"flow": [{}],
			"filename": "services/test_pcap/dump-2018-06-27_13:25:31.pcap",
			"src_ip": "10.10.3.126",
			"dst_port": 8080,
			"time": 1530098789655,
			"duration": 96,
			"inx": 0,
		}
	*/
	src, dst := t.net.Endpoints()
	var time, duration int
	if len(t.flowItems) == 0 {
		// No point in inserting this element, it has no data and even if we wanted to,
		// we can't timestamp it so the front-end can't display it either
		return true
	}

	time = t.flowItems[0].Time
	duration = t.flowItems[len(t.flowItems)-1].Time - time

	entry := db.FlowEntry{
		SrcPort:    int(t.srcPort),
		DstPort:    int(t.dstPort),
		SrcIp:      src.String(),
		DstIp:      dst.String(),
		Time:       time,
		Duration:   duration,
		NumPackets: t.numPackets,
		Blocked:    false,
		Tags:       []string{"tcp"},
		Suricata:   []string{},
		Filename:   t.source,
		Flow:       t.flowItems,
		Size:       t.totalSize,
		Flags:      make([]string, 0),
		Flagids:    make([]string, 0),
	}

	t.onComplete(entry)

	// Remove the connection from the pool for garbage collection.
	// The final ACK is not needed.
	//
	// Returning false would keep the TcpStream and its flowItems in memory
	// until flush is called, causing the assembler to use gigabytes of RAM.
	return true
}
