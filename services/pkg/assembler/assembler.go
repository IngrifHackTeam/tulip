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
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"tulip/pkg/db"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/reassembly"
)

type Service struct {
	Config

	Defragmenter  *ip4defrag.IPv4Defragmenter
	StreamFactory *TcpStreamFactory
	StreamPool    *reassembly.StreamPool

	AssemblerTcp *reassembly.Assembler
	AssemblerUdp *UDPAssembler

	toDb chan db.FlowEntry // Channel for processed flow entries

	stats Stats      // Statistics about processed packets, bytes, and flows
	mu    sync.Mutex // Mutex to protect stats updates
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

func NewAssemblerService(opts Config) *Service {
	streamFactory := &TcpStreamFactory{
		nonStrict: opts.NonStrict,
	}

	streamPool := reassembly.NewStreamPool(streamFactory)
	assemblerUdp := NewUDPAssembler()

	srv := &Service{
		Defragmenter:  ip4defrag.NewIPv4Defragmenter(),
		StreamFactory: streamFactory,
		StreamPool:    streamPool,

		AssemblerTcp: reassembly.NewAssembler(streamPool),
		AssemblerUdp: assemblerUdp,

		toDb: make(chan db.FlowEntry),
	}
	srv.Config = opts

	onComplete := func(fe db.FlowEntry) { srv.reassemblyCallback(fe) }
	srv.StreamFactory.OnComplete = onComplete

	go srv.handleInsertionQueue()

	return srv
}

func (s *Service) GetStats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.stats
}

// ProcessPcapPath processes a PCAP file from a given URI.
func (s *Service) ProcessPcapPath(
	ctx context.Context,
	fname string,
) error {
	file, err := os.Open(fname)
	if err != nil {
		return fmt.Errorf("failed to open PCAP file %s: %w", fname, err)
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create PCAP reader for %s: %w", fname, err)
	}

	return s.ProcessPcapReader(ctx, reader, fname)
}

// ProcessPcapReader processes packets from a pcapgo.Reader.
func (s *Service) ProcessPcapReader(
	ctx context.Context,
	handle *pcapgo.Reader,
	fname string,
) error {
	var source *gopacket.PacketSource

	linkType := handle.LinkType()
	switch linkType {
	case layers.LinkTypeIPv4:
		source = gopacket.NewPacketSource(handle, layers.LayerTypeIPv4)
	default:
		source = gopacket.NewPacketSource(handle, linkType)
	}

	source.Lazy = s.TcpLazy
	source.NoCopy = true

	return s.processPacketSrc(ctx, source, fname)
}

func (s *Service) processPacketSrc(
	ctx context.Context,
	src *gopacket.PacketSource,
	fname string,
) error {

	var (
		bytes     int64 = 0     // Total bytes processed
		processed int64 = 0     // Total packets processed
		finished  bool  = false // Whether we consumed all packets
	)

	toBeSkipped := s.checkProcessedCount(fname)
	slog.DebugContext(ctx, "assembler: skipping packets", "toBeSkipped", toBeSkipped, "file", fname)

	defer func() {
		// Update stats and database entry after processing
		// This is done in a deferred function to ensure it runs even if an error occurs

		s.mu.Lock()
		s.stats.Processed += processed
		s.stats.ProcessedBytes += bytes
		s.mu.Unlock()

		s.DB.InsertPcap(db.PcapFile{
			FileName: fname,
			Position: toBeSkipped + processed,
			Finished: finished,
		})
	}()

	s.FlushConnections()

	nodefrag := false
	lastFlush := time.Now()

	for packet := range src.Packets() {
		select {
		case <-ctx.Done():
			slog.Warn("context cancelled, stopping packet processing", "file", fname)
			finished = false
			return ctx.Err()
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
		shouldStop := s.processPacket(packet, fname, nodefrag)
		if shouldStop {
			finished = false
			return fmt.Errorf("processPacket returned true, stopping processing for %s", fname)
		}

		if s.shouldFlushConnections(lastFlush) {
			s.FlushConnections()
			lastFlush = time.Now()
		}
	}

	finished = true
	return nil
}

// FlushConnections closes and saves connections that are older than the configured timeouts.
func (s *Service) FlushConnections() {
	thresholdTcp := time.Now().Add(-s.ConnectionTcpTimeout)
	thresholdUdp := time.Now().Add(-s.ConnectionUdpTimeout)
	flushed, closed, discarded := 0, 0, 0

	if s.ConnectionTcpTimeout != 0 {
		flushed, closed = s.AssemblerTcp.FlushCloseOlderThan(thresholdTcp)
		discarded = s.Defragmenter.DiscardOlderThan(thresholdTcp)
	}

	if flushed != 0 || closed != 0 || discarded != 0 {
		slog.Info("Flushed connections", "flushed", flushed, "closed", closed, "discarded", discarded)
	}

	if s.ConnectionUdpTimeout != 0 {
		udpFlows := s.AssemblerUdp.CompleteOlderThan(thresholdUdp)
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
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

// processPacket handles a single packet: skipping, defragmentation, protocol dispatch (TCP/UDP), and error handling.
// Returns true if processing should stop.
func (s *Service) processPacket(packet gopacket.Packet, fname string, nodefrag bool) bool {
	// defrag the IPv4 packet if required
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if !nodefrag && ip4Layer != nil {
		ip4 := ip4Layer.(*layers.IPv4)
		l := ip4.Length
		newip4, err := s.Defragmenter.DefragIPv4(ip4)
		if err != nil {
			slog.Error("Error while de-fragmenting", "err", err)
			return true
		} else if newip4 == nil {
			return false // packet fragment, we don't have whole packet yet.
		}
		if newip4.Length != l {
			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				panic("Not a PacketBuilder")
			}
			nextDecoder := newip4.NextLayerType()
			nextDecoder.Decode(newip4.Payload, pb)
		}
	}

	transport := packet.TransportLayer()
	if transport == nil {
		return false
	}

	switch transport.LayerType() {
	case layers.LayerTypeTCP:
		tcp := transport.(*layers.TCP)
		flow := packet.NetworkLayer().NetworkFlow()
		captureInfo := packet.Metadata().CaptureInfo
		captureInfo.AncillaryData = []any{fname}
		context := &Context{CaptureInfo: captureInfo}
		s.AssemblerTcp.AssembleWithContext(flow, tcp, context)
	case layers.LayerTypeUDP:
		udp := transport.(*layers.UDP)
		flow := packet.NetworkLayer().NetworkFlow()
		captureInfo := packet.Metadata().CaptureInfo
		s.AssemblerUdp.Assemble(flow, udp, &captureInfo, fname)
	default:
		slog.Warn("Unsupported transport layer", "layer", transport.LayerType().String(), "file", fname)
	}
	return false
}

// shouldFlushConnections determines if it's time to flush connections based on the interval.
func (s *Service) shouldFlushConnections(lastFlush time.Time) bool {
	return s.FlushInterval != 0 && lastFlush.Add(s.FlushInterval).Unix() < time.Now().Unix()
}

// TODO; FIXME; RDJ; this is kinda gross, but this is PoC level code
func (s *Service) reassemblyCallback(entry db.FlowEntry) {
	// we first try to parse it as HTTP to decompress the body if
	// it was compressed with gzip or similar.
	s.parseHttpFlow(&entry)

	// Preprocess the flow items
	sanitizeFlowItemData(&entry)

	// search for flags in the flow items
	applyFlagRegexTags(&entry, s.FlagRegex)

	// queue the flow for insertion into the database
	s.toDb <- entry
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
		case entry := <-s.toDb:
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
