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
	"strings"
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

	defragmenter *ip4defrag.IPv4Defragmenter

	tcpStreamFactory *TcpStreamFactory
	tcpStreamPool    *reassembly.StreamPool
	tcpAssembler     *reassembly.Assembler

	udpAssembler *UDPAssembler

	toDbCh chan db.FlowEntry // Channel for processed flow entries

	ctx   context.Context // Context for cancellation
	stats Stats           // Statistics about processed packets, bytes, and flows
	mu    sync.Mutex      // Mutex to protect stats updates
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

	FlagIdUrl string // URL del servizio flagid
}

func NewAssemblerService(ctx context.Context, opts Config) *Service {
	var (
		tcpStreamFactory = &TcpStreamFactory{nonStrict: opts.NonStrict}
		tcpStreamPool    = reassembly.NewStreamPool(tcpStreamFactory)
		tcpAssembler     = reassembly.NewAssembler(tcpStreamPool)
	)

	udpAssembler := NewUDPAssembler()

	srv := &Service{
		Config: opts,

		defragmenter: ip4defrag.NewIPv4Defragmenter(),

		tcpStreamFactory: tcpStreamFactory,
		tcpStreamPool:    tcpStreamPool,
		tcpAssembler:     tcpAssembler,

		udpAssembler: udpAssembler,

		toDbCh: make(chan db.FlowEntry),

		ctx: ctx,
	}

	onComplete := func(fe db.FlowEntry) { srv.reassemblyCallback(fe) }
	srv.tcpStreamFactory.OnComplete = onComplete

	go srv.handleInsertionQueue()

	return srv
}

func (s *Service) GetStats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.stats
}

func (s *Service) ProcessPacketSrc(src *gopacket.PacketSource, sourceName string) error {
	var (
		bytes     int64 = 0     // Total bytes processed
		processed int64 = 0     // Total packets processed
		finished  bool  = false // Whether we consumed all packets
	)

	toBeSkipped := s.checkProcessedCount(sourceName)
	slog.DebugContext(s.ctx, "assembler: skipping packets", "toBeSkipped", toBeSkipped, "file", sourceName)

	defer func() {
		// Update stats and database entry after processing
		// This is done in a deferred function to ensure it runs even if an error occurs

		s.mu.Lock()
		s.stats.Processed += processed
		s.stats.ProcessedBytes += bytes
		s.mu.Unlock()

		s.DB.InsertPcap(db.PcapFile{
			FileName: sourceName,
			Position: toBeSkipped + processed,
			Finished: finished,
		})
	}()

	nodefrag := false
	lastFlush := time.Now()

	for packet := range src.Packets() {
		select {
		case <-s.ctx.Done():
			slog.Warn("context cancelled, stopping packet processing", "file", sourceName)
			finished = false
			return s.ctx.Err()
		default:
		}

		// skip until toBeSkipped is 0
		if toBeSkipped >= 0 {
			toBeSkipped--
			continue
		}

		processed++

		data := packet.Data()
		bytes += int64(len(data))
		shouldStop := s.processPacket(packet, sourceName, nodefrag)
		if shouldStop {
			finished = false
			return fmt.Errorf("processPacket returned true, stopping processing for %s", sourceName)
		}

		// TODO: this is not thread-safe, but we can't lock a mutex every time we process a packet!
		lastFlush = s.flushIfNeeded(lastFlush)
	}

	finished = true
	return nil
}

// flushIfNeeded calls FlushConnections if the current time exceeds the last flush time
// by the configured FlushInterval and returns the new last flush time.
func (s *Service) flushIfNeeded(lastFlush time.Time) time.Time {
	if s.FlushInterval == 0 || lastFlush.Add(s.FlushInterval).Unix() >= time.Now().Unix() {
		return lastFlush
	}
	s.FlushConnections()
	return time.Now()
}

// shouldFlushConnections determines if it's time to flush connections based on the interval.
func (s *Service) shouldFlushConnections(lastFlush time.Time) bool {
	return s.FlushInterval != 0 && lastFlush.Add(s.FlushInterval).Unix() < time.Now().Unix()
}

// FlushConnections closes and saves connections that are older than the configured timeouts.
func (s *Service) FlushConnections() {
	thresholdTcp := time.Now().Add(-s.ConnectionTcpTimeout)
	thresholdUdp := time.Now().Add(-s.ConnectionUdpTimeout)
	flushed, closed, discarded := 0, 0, 0

	if s.ConnectionTcpTimeout != 0 {
		flushed, closed = s.tcpAssembler.FlushCloseOlderThan(thresholdTcp)
		discarded = s.defragmenter.DiscardOlderThan(thresholdTcp)
	}

	if flushed != 0 || closed != 0 || discarded != 0 {
		slog.Info("Flushed connections", "flushed", flushed, "closed", closed, "discarded", discarded)
	}

	if s.ConnectionUdpTimeout != 0 {
		udpFlows := s.udpAssembler.CompleteOlderThan(thresholdUdp)
		for _, flow := range udpFlows {
			s.reassemblyCallback(*flow)
		}

		if len(udpFlows) != 0 {
			slog.Info("Assembled UDP flows", "count", len(udpFlows))
		}
	}
}

// checkProcessedCount returns the count of already processed packets for a given file.
func (s *Service) checkProcessedCount(fname string) int64 {
	exists, file := s.DB.GetPcap(fname)
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

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo { return c.CaptureInfo }

// processPacket handles a single packet: skipping, defragmentation, protocol dispatch (TCP/UDP), and error handling.
// Returns true if processing should stop.
func (s *Service) processPacket(packet gopacket.Packet, fname string, noDefrag bool) (stop bool) {

	// defrag the packet, sequentially
	if !noDefrag {
		complete, err := s.defragPacket(packet)
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
	context := &Context{packet.Metadata().CaptureInfo, fname}

	switch transport.LayerType() {
	case layers.LayerTypeTCP:
		s.tcpAssembler.AssembleWithContext(flow, transport.(*layers.TCP), context)
	case layers.LayerTypeUDP:
		s.udpAssembler.AssembleWithContext(flow, transport.(*layers.UDP), context)
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
func (s *Service) defragPacket(packet gopacket.Packet) (complete bool, err error) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return true, nil // No IPv4 layer found, nothing to defragment
	}

	ip4 := ip4Layer.(*layers.IPv4)
	oldLen := ip4.Length

	newip4, defragErr := s.defragmenter.DefragIPv4(ip4)
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
func (s *Service) reassemblyCallback(entry db.FlowEntry) {
	// we first try to parse it as HTTP to decompress the body if
	// it was compressed with gzip or similar.
	s.parseHttpFlow(&entry)

	// Preprocess the flow items
	sanitizeFlowItemData(&entry)

	// search for flags in the flow items
	applyFlagRegexTags(&entry, s.FlagRegex)

	// queue the flow for insertion into the database
	s.toDbCh <- entry
}

// applyFlagRegexTags searches for flags in flow items using a regex pattern
// and if found, adds them to the entry's tags and flags.
//
// This assumes the `Data` part of the flowItem is already pre-processed,
// s.t. we can run regex tags over the payload directly.
func applyFlagRegexTags(entry *db.FlowEntry, flagRegex *regexp.Regexp) {
	if flagRegex == nil {
		return
	}

	// for each flow item in the entry, search for flags using the regex
	for idx := 0; idx < len(entry.Flow); idx++ {
		flags, tags := searchForFlagsInItem(&entry.Flow[idx], flagRegex)

		entry.Tags = appendUnique(entry.Tags, tags...)
		entry.Flags = appendUnique(entry.Flags, flags...)
	}
}

// searchForFlagsInItem returns flags and associated tags found in a flow item
// using the provided regex. It returns empty slices if no flags are found.
func searchForFlagsInItem(
	item *db.FlowItem,
	flagRegex *regexp.Regexp,
) (flags []string, tags []string) {
	matches := flagRegex.FindAllSubmatch(item.Raw, -1)
	if len(matches) == 0 {
		return // No matches found, skip further processing
	}

	if item.From == "c" {
		tags = append(tags, "flag-in")
	} else {
		tags = append(tags, "flag-out")
	}

	// Add the flags
	for _, match := range matches {
		var flag string
		flag = string(match[0])
		flags = appendUnique(flags, flag)
	}
	return
}

// sanitizeFlowItemData copies the raw data of each flow item into
// the Data field, replacing non-printable characters with '.'.
func sanitizeFlowItemData(flow *db.FlowEntry) {
	for idx := range flow.Flow {
		flowItem := &flow.Flow[idx]
		flowItem.Data = sanitizeRawData(flowItem.Raw)
	}
}

// sanitizeRawData filters the raw byte slice to only include printable characters,
// replacing non-printable characters with '.'.
func sanitizeRawData(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))

	// Filter the data string down to only printable characters
	for _, c := range raw {
		if (c >= 32 && c <= 126) || c == '\t' || c == '\r' || c == '\n' {
			b.WriteByte(c)
		} else {
			b.WriteByte('.') // Replace non-printable characters with '.'
		}
	}
	return b.String()
}

func (s *Service) handleInsertionQueue() {
	queueSize := 200

	queue := make([]db.FlowEntry, 0, queueSize)

	// we debounce the insertion of flows into the database
	// by collecting them in a queue and inserting them in batches

	for {
		select {
		case <-s.ctx.Done():
			slog.Info("context cancelled, stopping insertion queue and dropping remaining flows")
			return
		case entry := <-s.toDbCh:
			// Add the entry to the queue
			queue = append(queue, entry)
			if len(queue) >= queueSize {
				s.insertFlows(queue)
				queue = queue[:0] // Clear the queue
			}
		case <-time.After(500 * time.Millisecond):
			// If the timer ticks, insert all entries in the queue
			if len(queue) > 0 {
				s.insertFlows(queue)
				queue = queue[:0] // Clear the queue
			}
		}
	}

}

func (s *Service) insertFlows(flows []db.FlowEntry) {
	if len(flows) == 0 {
		return
	}

	err := s.DB.InsertFlows(context.Background(), flows)
	if err != nil {
		slog.Error("Failed to insert flows into database", "err", err)
	}
}
