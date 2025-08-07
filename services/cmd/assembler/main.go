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

package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"tulip/pkg/analysis"
	"tulip/pkg/assembler"
	"tulip/pkg/db"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var gDB db.Database

const streamdocLimit = 6_000_000 - 0x1000 // 16 MB (6 + (4/3)*6) - some overhead

var rootCmd = &cobra.Command{
	Use:   "assembler",
	Short: "PCAP assembler TCP ingest service",
	Long:  `Assembler watches a directory for incoming PCAP files, processes them, and assembles TCP streams.`,
	Run:   runAssembler,
}

func init() {
	rootCmd.Flags().String("mongo", "localhost:27017", "MongoDB DNS name + port (e.g. mongo:27017)")
	rootCmd.Flags().String("watch-dir", "/tmp/ingestor_ready", "Directory to watch for incoming PCAP files")
	rootCmd.Flags().String("flag", "", "Flag regex, used for flag in/out tagging")
	rootCmd.Flags().String("flush-interval", "15s", "Interval for flushing connections (e.g. 15s, 1m)")
	rootCmd.Flags().Bool("tcp-lazy", false, "Enable lazy decoding for TCP packets")
	rootCmd.Flags().Bool("experimental", false, "Enable experimental features")
	rootCmd.Flags().Bool("nonstrict", false, "Enable non-strict mode for TCP stream assembly")
	rootCmd.Flags().String("connection-timeout", "30s", "Connection timeout for both TCP and UDP flows (e.g. 30s, 1m)")
	rootCmd.Flags().Bool("pperf", false, "Enable performance profiling (experimental)")
	rootCmd.Flags().Bool("verbose", false, "Enable verbose logging")
	rootCmd.Flags().Int("workers", 2, "Number of worker threads to use for processing PCAP files")

	_ = viper.BindPFlag("mongo", rootCmd.Flags().Lookup("mongo"))
	_ = viper.BindPFlag("watch-dir", rootCmd.Flags().Lookup("watch-dir"))
	_ = viper.BindPFlag("flag", rootCmd.Flags().Lookup("flag"))
	_ = viper.BindPFlag("flush-interval", rootCmd.Flags().Lookup("flush-interval"))
	_ = viper.BindPFlag("tcp-lazy", rootCmd.Flags().Lookup("tcp-lazy"))
	_ = viper.BindPFlag("experimental", rootCmd.Flags().Lookup("experimental"))
	_ = viper.BindPFlag("nonstrict", rootCmd.Flags().Lookup("nonstrict"))
	_ = viper.BindPFlag("connection-timeout", rootCmd.Flags().Lookup("connection-timeout"))
	_ = viper.BindPFlag("pperf", rootCmd.Flags().Lookup("pperf"))
	_ = viper.BindPFlag("verbose", rootCmd.Flags().Lookup("verbose"))
	_ = viper.BindPFlag("workers", rootCmd.Flags().Lookup("workers"))

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvPrefix("TULIP")
}

func runAssembler(cmd *cobra.Command, args []string) {
	verbose := viper.GetBool("verbose")
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	// Setup logging
	logger := slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:      level,
		TimeFormat: "2006-01-02 15:04:05",
	}))
	slog.SetDefault(logger)

	// Get config from viper
	mongodb := viper.GetString("mongo")
	watchDir := viper.GetString("watch-dir")
	flagRegexStr := viper.GetString("flag")
	flushIntervalStr := viper.GetString("flush-interval")
	tcpLazy := viper.GetBool("tcp-lazy")
	experimental := viper.GetBool("experimental")
	nonstrict := viper.GetBool("nonstrict")
	connectionTimeoutStr := viper.GetString("connection-timeout")
	pperf := viper.GetBool("pperf")
	workers := viper.GetInt("workers")

	if pperf {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	// Connect to MongoDB
	dbString := "mongodb://" + mongodb
	slog.Info("Connecting to MongoDB...", slog.String("uri", dbString))

	var err error
	gDB, err = db.NewMongoDatabase(context.TODO(), dbString)
	if err != nil {
		slog.Error("Failed to connect to MongoDB", slog.Any("err", err))
		os.Exit(1)
	}
	slog.Info("Connected to MongoDB")

	slog.Info("Configuring MongoDB database...")
	err = gDB.ConfigureDatabase()
	if err != nil {
		slog.Error("Failed to configure MongoDB database", slog.Any("err", err))
		os.Exit(1)
	}

	// Parse flush interval
	var flushInterval time.Duration
	if flushIntervalStr != "" {
		var err error
		flushInterval, err = time.ParseDuration(flushIntervalStr)
		if err != nil {
			slog.Error("Invalid flush-interval", slog.String("flush-interval", flushIntervalStr), slog.Any("err", err))
			os.Exit(1)
		}
	}

	// Parse connection timeout
	var connectionTimeout time.Duration
	if connectionTimeoutStr != "" {
		var err error
		connectionTimeout, err = time.ParseDuration(connectionTimeoutStr)
		if err != nil {
			slog.Error("Invalid connection-timeout", slog.String("connection-timeout", connectionTimeoutStr), slog.Any("err", err))
			os.Exit(1)
		}
	}

	// global ctx
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Create assembler service
	flagIdUrl := os.Getenv("FLAGID_URL")
	config := assembler.Config{
		DB:                   gDB,
		TcpLazy:              tcpLazy,
		Experimental:         experimental,
		NonStrict:            nonstrict,
		FlushInterval:        flushInterval,
		ConnectionTcpTimeout: connectionTimeout,
		ConnectionUdpTimeout: connectionTimeout,
		FlagIdUrl:            flagIdUrl,
		StreamdocLimit:       streamdocLimit,
		Workers:              workers,
	}

	// create a new assembler service instance
	service := assembler.NewAssemblerService(ctx, config)

	flagAnalyzer, err := analysis.FlagAnalyzer(flagRegexStr)
	if err != nil {
		slog.Error("Failed to create flag analyzer", slog.Any("err", err))
		os.Exit(1)
	}

	analysisPipeline := analysis.NewSequence(
		// Order matters here!
		// Each analyzer will be run on the output of the previous one.

		// We first try to parse it as HTTP to decompress the body if
		// it was compressed with gzip or similar.
		analysis.HttpAnalyzer(experimental, int64(streamdocLimit)),

		// ... then we search for flags in the flow items
		flagAnalyzer,

		// ... and finally we humanize the flow items
		analysis.Humanizer(),
	)

	var (
		pcapChan     = make(chan string) // Synchronous channel for PCAP file paths
		analyzedChan = make(chan db.FlowEntry, 100)
	)

	// 1. Watch the directory for new PCAP files and push them to the pcapChan
	go watchForPcaps(ctx, watchDir, pcapChan)

	// 2. Assemble PCAP packets and create flows
	go func() {
		for fullPath := range pcapChan {
			processPcapFile(ctx, service, fullPath)
		}
	}()

	// 2. Analyze entries and queue them for insertion into the database
	go func() {
		for entry := range service.Assembled() {
			if err := analysisPipeline.Run(&entry); err != nil {
				slog.Warn("Failed to run analysis pipeline", slog.Any("err", err))
			}
			analyzedChan <- entry // Send the entry to the insertion queue
		}
	}()

	// 3. Insert assembled flows into the database
	go processDbChan(analyzedChan)

	<-ctx.Done() // Wait for context cancellation
	slog.Info("Shutting down assembler service...")
}

func watchForPcaps(ctx context.Context, watchDir string, pcapChan chan<- string) {

	// Use polling for simplicity and reliability
	pollInterval := 2 * time.Second
	seen := make(map[string]struct{})

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		files, err := os.ReadDir(watchDir)
		if err != nil {
			slog.Error("Failed to read watch directory", slog.Any("err", err))
			time.Sleep(pollInterval)
			continue
		}

		for i, file := range files {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if file.IsDir() {
				continue
			}
			name := file.Name()
			if filepath.Ext(name) != ".pcap" {
				continue
			}
			fullPath := filepath.Join(watchDir, name)
			if _, ok := seen[fullPath]; ok {
				continue
			}
			seen[fullPath] = struct{}{}

			slog.Info("ingesting new PCAP file", slog.String("file", fullPath), "idx", i+1, "of", len(files))
			pcapChan <- fullPath
		}

		slog.Info("waiting for new PCAP files", "wait", pollInterval)
		time.Sleep(pollInterval)
	}
}

func processPcapFile(ctx context.Context, service *assembler.Service, fullPath string) {
	startTime := time.Now()

	defer func() {
		if r := recover(); r != nil {
			slog.Error("Recovered from panic in ProcessPcapHandle", "error", r, "file", fullPath)
		}
	}()

	file, err := os.Open(fullPath)
	if err != nil {
		slog.Error("Failed to open PCAP file", slog.Any("err", err), slog.String("file", fullPath))
		return
	}
	defer func() { _ = file.Close() }()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		slog.Error("Failed to create PCAP reader", slog.Any("err", err), slog.String("file", fullPath))
		return
	}

	oldStats := service.GetStats()
	err = processPcapReader(ctx, service, reader, fullPath)
	if err != nil {
		slog.Error("Failed to process PCAP file", slog.Any("err", err), slog.String("file", fullPath))
	}
	newStats := service.GetStats()

	elapsed := time.Since(startTime)

	totPkts := newStats.Processed - oldStats.Processed
	totBytes := newStats.ProcessedBytes - oldStats.ProcessedBytes
	pktsPerSec := (float64(totPkts) / elapsed.Seconds())
	totBytesPerSec := float64(totBytes) / elapsed.Seconds()

	if totPkts == 0 {
		slog.Info("No packets processed", "path", fullPath)
	} else {
		slog.Info("Processed PCAP file",
			"path", fullPath,
			"elapsed_ms", elapsed.Milliseconds(),
			"packets", totPkts,
			"bytes", totBytes,
			"pps", fmt.Sprintf("%.2f", pktsPerSec),
			"MB_per_sec", fmt.Sprintf("%.2f", totBytesPerSec/1e6),
		)
	}
}

// processPcapReader creates a gopacket PacketSource from a pcapgo.Reader and processes
// packets using the assembler service.
func processPcapReader(ctx context.Context, s *assembler.Service, handle *pcapgo.Reader, fname string) error {
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

	return s.ProcessPacketSrc(ctx, source, fname)
}

func processDbChan(assembled <-chan db.FlowEntry) {
	// we debounce the insertion of flows into the database
	// by collecting them in a queue and inserting them in batches

	queueSize := 200
	queue := make([]db.FlowEntry, 0, queueSize)

	for {
		select {
		case entry, ok := <-assembled:
			if !ok {
				// Channel closed, insert any remaining entries in the queue
				if len(queue) > 0 {
					insertFlows(queue)
				}
				return
			}

			// Add the entry to the queue
			queue = append(queue, entry)
			if len(queue) >= queueSize {
				insertFlows(queue)
				queue = queue[:0] // Clear the queue
			}

		case <-time.After(500 * time.Millisecond):
			// If the timer ticks, insert all entries in the queue
			if len(queue) > 0 {
				insertFlows(queue)
				queue = queue[:0] // Clear the queue
			}
		}
	}

}

func insertFlows(flows []db.FlowEntry) {
	if len(flows) == 0 {
		return
	}

	err := gDB.InsertFlows(context.Background(), flows)
	if err != nil {
		slog.Error("Failed to insert flows into database", "err", err)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		slog.Error("Command failed", slog.Any("err", err))
		os.Exit(1)
	}
}
