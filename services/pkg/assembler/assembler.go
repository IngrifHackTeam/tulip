// SPDX-FileCopyrightText: 2022 Rick de Jager <rickdejager99@gmail.com>
// SPDX-FileCopyrightText: 2022 erdnaxe <erdnaxe@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 - 2024 gfelber <34159565+gfelber@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 - 2025 Eyad Issa <eyadlorenzo@gmail.com>
// SPDX-FileCopyrightText: 2023 Max Groot <19346100+MaxGroot@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 Sijisu <mail@sijisu.eu>
// SPDX-FileCopyrightText: 2023 liskaant <50048810+liskaant@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 liskaant <liskaant@gmail.com>
// SPDX-FileCopyrightText: 2023 meme-lord <meme-lord@users.noreply.github.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"
	"tulip/pkg/db"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

type Service struct {
	Config

	// Stage 1: level 3 defragmentation

	defragmenter *ip4defrag.IPv4Defragmenter

	// Stage 2: TCP/UDP reassembly

	tcpStreamFactory *TcpStreamFactory
	tcpStreamPool    *reassembly.StreamPool
	tcpAssembler     *reassembly.Assembler

	udpAssembler *UDPAssembler

	// Stage 3: returning assembled flows

	assembled chan db.FlowEntry // Channel for processed flow entries

	// Misc state

	stats     Stats        // Statistics about processed packets, bytes, and flows
	mu        sync.Mutex   // Mutex to protect stats updates
	flushTick *time.Ticker // Ticker for flushing connections
}

type Stats struct {
	Processed      int64 // Total number of processed packets
	ProcessedBytes int64 // Total number of processed bytes
	Flows          int64 // Total number of flows processed
}

type Config struct {
	DB            db.Database    // the database to use for storing flows
	FlushInterval time.Duration  // Interval to flush non-terminated connections
	FlagRegex     *regexp.Regexp // Regex to apply for flagging flows
	TcpLazy       bool           // Lazy decoding for TCP packets
	Experimental  bool           // Experimental features enabled
	NonStrict     bool           // Non-strict mode for TCP stream assembly

	ConnectionTcpTimeout time.Duration
	ConnectionUdpTimeout time.Duration

	FlagIdUrl      string // URL del servizio flagid
	StreamdocLimit int    // Limit for streamdoc size, used in analysis
}

func NewAssemblerService(ctx context.Context, opts Config) *Service {
	var (
		tcpStreamFactory = &TcpStreamFactory{nonStrict: opts.NonStrict, streamdocLimit: opts.StreamdocLimit}
		tcpStreamPool    = reassembly.NewStreamPool(tcpStreamFactory)
		tcpAssembler     = reassembly.NewAssembler(tcpStreamPool)
	)

	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 5 * time.Second // Default flush interval if not set
	}

	udpAssembler := NewUDPAssembler(opts.StreamdocLimit)

	srv := &Service{
		Config: opts,

		defragmenter: ip4defrag.NewIPv4Defragmenter(),

		tcpStreamFactory: tcpStreamFactory,
		tcpStreamPool:    tcpStreamPool,
		tcpAssembler:     tcpAssembler,

		udpAssembler: udpAssembler,

		assembled: make(chan db.FlowEntry),

		flushTick: time.NewTicker(opts.FlushInterval),
	}

	onComplete := func(fe db.FlowEntry) { srv.reassemblyCallback(fe) }
	srv.tcpStreamFactory.OnComplete = onComplete

	return srv
}

// Assembled returns a channel that emits assembled flow entries.
func (s *Service) Assembled() <-chan db.FlowEntry {
	return s.assembled
}

func (a *Service) GetStats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.stats
}

func (a *Service) ProcessPacketSrc(ctx context.Context, src *gopacket.PacketSource, sourceName string) error {

	slog.DebugContext(ctx, "assembler: starting packet processing", "file", sourceName)

	var (
		bytes     int64 = 0     // Total bytes processed
		position  int64 = 0     // Total packets processed, including skipped
		processed int64 = 0     // Packets processed after skipping
		finished  bool  = false // Whether we consumed all packets
	)

	toBeSkipped := a.checkProcessedCount(sourceName)
	slog.DebugContext(ctx, "assembler: skipping packets", "toBeSkipped", toBeSkipped, "file", sourceName)

	defer func() {
		// Update stats and database entry after processing
		// This is done in a deferred function to ensure it runs even if an error occurs

		a.mu.Lock()
		a.stats.Processed += processed
		a.stats.ProcessedBytes += bytes
		a.mu.Unlock()

		slog.Debug("assembler: updating database entry",
			"file", sourceName,
			"position", position,
			"finished", finished,
		)

		a.DB.InsertPcap(db.PcapFile{
			FileName: sourceName,
			Position: position,
			Finished: finished,
		})
	}()

	nodefrag := false

	for packet := range src.Packets() {
		select {
		case <-a.flushTick.C:
			a.FlushConnections()
		case <-ctx.Done():
			slog.Warn("context cancelled, stopping packet processing", "file", sourceName)
			finished = false
			return ctx.Err()
		default:
		}

		position++
		if position <= toBeSkipped {
			continue
		}

		data := packet.Data()

		processed++
		bytes += int64(len(data))
		shouldStop := a.processPacket(packet, sourceName, nodefrag)
		if shouldStop {
			finished = false
			return fmt.Errorf("processPacket returned true, stopping processing for %s", sourceName)
		}
	}

	if position < toBeSkipped {
		panic(fmt.Sprintf("assembler: position %d is less than toBeSkipped %d for file %s", position, toBeSkipped, sourceName))
	}

	slog.Debug("assembler: finished processing packets",
		"file", sourceName,
		"processed", processed,
		"bytes", bytes,
		"finished", finished,
	)

	finished = true
	return nil
}

// flushIfNeeded calls FlushConnections if the current time exceeds the last flush time
// by the configured FlushInterval and returns the new last flush time.
func (a *Service) flushIfNeeded(lastFlush time.Time) time.Time {
	if a.FlushInterval == 0 || lastFlush.Add(a.FlushInterval).Unix() >= time.Now().Unix() {
		return lastFlush
	}
	a.FlushConnections()
	return time.Now()
}

// FlushConnections closes and saves connections that are older than the configured timeouts.
func (a *Service) FlushConnections() {
	thresholdTcp := time.Now().Add(-a.ConnectionTcpTimeout)
	thresholdUdp := time.Now().Add(-a.ConnectionUdpTimeout)
	flushed, closed, discarded := 0, 0, 0

	if a.ConnectionTcpTimeout != 0 {
		flushed, closed = a.tcpAssembler.FlushCloseOlderThan(thresholdTcp)
		discarded = a.defragmenter.DiscardOlderThan(thresholdTcp)
	}

	if flushed != 0 || closed != 0 || discarded != 0 {
		slog.Info("Flushed connections", "flushed", flushed, "closed", closed, "discarded", discarded)
	}

	if a.ConnectionUdpTimeout != 0 {
		udpFlows := a.udpAssembler.CompleteOlderThan(thresholdUdp)
		for _, flow := range udpFlows {
			a.reassemblyCallback(*flow)
		}

		if len(udpFlows) != 0 {
			slog.Info("Assembled UDP flows", "count", len(udpFlows))
		}
	}
}

// checkProcessedCount returns the count of already processed packets for a given file.
func (a *Service) checkProcessedCount(fname string) int64 {
	exists, file := a.DB.GetPcap(fname)
	if exists {
		return file.Position
	}
	return 0 // file not found, return 0 to process all packets
}

// Context implements reassembly.AssemblerContext
type Context struct {
	gopacket.CaptureInfo
	FileName string // FileName is the name of the file being processed
}

func (c Context) GetCaptureInfo() gopacket.CaptureInfo { return c.CaptureInfo }

// processPacket handles a single packet: skipping, defragmentation, protocol dispatch (TCP/UDP), and error handling.
// Returns true if processing should stop.
func (a *Service) processPacket(packet gopacket.Packet, fname string, noDefrag bool) (stop bool) {

	// defrag the packet, sequentially
	if !noDefrag {
		complete, err := a.defragPacket(packet)
		if err != nil {
			return true // stop processing due to error
		} else if !complete {
			return false // wait for more fragments
		}
	}

	transport := packet.TransportLayer()
	if transport == nil {
		return false // skip packet
	}

	flow := packet.NetworkLayer().NetworkFlow()
	context := Context{packet.Metadata().CaptureInfo, fname}

	switch transport.LayerType() {
	case layers.LayerTypeTCP:
		a.tcpAssembler.AssembleWithContext(flow, transport.(*layers.TCP), context)
	case layers.LayerTypeUDP:
		a.udpAssembler.AssembleWithContext(flow, transport.(*layers.UDP), context)
	default:
		slog.Warn("Unsupported transport layer", "layer", transport.LayerType().String(), "file", fname)
	}

	return false // continue processing packets
}

// defragPacket attempts to defragment an IPv4 packet.
//
// Returns true if the packet is complete, false if it is still a fragment,
// and an error if defragmentation fails.
// If the packet is successfully defragmented, it decodes the next protocol layer.
func (a *Service) defragPacket(packet gopacket.Packet) (complete bool, err error) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return true, nil // No IPv4 layer found, nothing to defragment
	}

	ip4 := ip4Layer.(*layers.IPv4)
	oldLen := ip4.Length

	newip4, defragErr := a.defragmenter.DefragIPv4(ip4)
	if defragErr != nil {
		slog.Error("Error while de-fragmenting", "err", defragErr)
		return false, defragErr // stop processing due to error
	} else if newip4 == nil {
		// packet fragment, we don't have whole packet yet.
		return false, nil // wait for more fragments
	}

	// If the length of the IPv4 packet has changed after defragmentation,
	// it means we now have a complete packet with a potentially new payload.
	// We need to decode the next protocol layer (e.g., TCP, UDP) from this payload.
	if newip4.Length != oldLen {
		// Attempt to cast the packet to a PacketBuilder, which is required
		// for decoding the next protocol layer.
		pb, ok := packet.(gopacket.PacketBuilder)
		if !ok {
			// Panic if the packet does not implement PacketBuilder.
			// This should not happen in normal operation.
			panic("Packet does not implement gopacket.PacketBuilder, cannot decode next layer")
		}
		// Decode the next layer using the new payload.
		nextDecoder := newip4.NextLayerType()
		nextDecoder.Decode(newip4.Payload, pb)
	}

	return true, nil
}

// reassemblyCallback is called when a flow is completed.
func (a *Service) reassemblyCallback(entry db.FlowEntry) {
	a.assembled <- entry
}
