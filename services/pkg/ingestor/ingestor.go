// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

package ingestor

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"
)

type Ingestor struct {
	TmpDir         string
	DestDir        string
	RotateInterval time.Duration
}

func (i *Ingestor) Serve(addr string) error {

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start TCP server: %w", err)
	}
	defer func() {
		err = ln.Close()
		if err != nil {
			slog.Error("Failed to close listener", slog.Any("err", err))
		}
	}()

	slog.Info("Listening for incoming PCAP connections...", slog.String("address", addr))

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error("Failed to accept connection", slog.Any("err", err))
			continue
		}
		go i.handlePcapConnection(conn)
	}
}

// handlePcapConnection handles a single incoming PCAP-over-IP connection.
func (i *Ingestor) handlePcapConnection(conn net.Conn) {
	defer func() {
		err := conn.Close()
		if err != nil {
			slog.Error("Failed to close connection", slog.Any("err", err))
		}
	}()

	clientAddr := conn.RemoteAddr().String()
	clientID := sanitizeFilename(clientAddr)
	slog.Info("Accepted new PCAP connection", slog.String("client", clientAddr))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rw := NewRotatingPCAPWriter(conn, i.TmpDir, i.DestDir, clientID, i.RotateInterval)
	err := rw.Start(ctx)
	if err != nil {
		slog.Error("Failed to start PCAP writer", slog.String("client", clientAddr), slog.Any("err", err))
		return
	}

	slog.Info("Finished ingesting PCAP connection", slog.String("client", clientAddr))
}

// sanitizeFilename replaces invalid characters in a filename with underscores.
func sanitizeFilename(s string) string {
	r := []rune(s)
	for i, c := range r {
		if c == ':' || c == '/' || c == '\\' {
			r[i] = '_'
		}
	}
	return string(r)
}
