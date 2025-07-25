// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package analysis

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
	"tulip/pkg/db"

	"github.com/andybalholm/brotli"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHttpAnalyzer_RequestPlain(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	flow := &db.FlowEntry{
		Flow: []db.FlowItem{{Raw: raw, From: "c"}},
	}
	analyzer := HttpAnalyzer(false, 0)
	err := analyzer.Run(flow)
	assert.NoError(t, err, "Unexpected error")
	assert.Contains(t, flow.Tags, "http", "Expected 'http' tag")
}

func TestHttpAnalyzer_ResponseGzip(t *testing.T) {
	body := []byte("hello world")
	gzipped := makeGzip(t, body)
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n")
	raw = append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n"), gzipped...)
	flow := &db.FlowEntry{
		Flow: []db.FlowItem{{Raw: raw, From: "s"}},
	}
	analyzer := HttpAnalyzer(false, 0)
	err := analyzer.Run(flow)
	assert.NoError(t, err, "Unexpected error")
	assert.Contains(t, flow.Tags, "http", "Expected 'http' tag")
}

func TestHttpAnalyzer_RequestWithBrotli(t *testing.T) {
	body := []byte("hello world")
	brBytes := makeBrotli(t, body)

	raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Encoding: br\r\nContent-Length: %d\r\n\r\n")
	raw = append([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nContent-Encoding: br\r\n\r\n"), brBytes...)
	flow := &db.FlowEntry{
		Flow: []db.FlowItem{{Raw: raw, From: "c"}},
	}
	analyzer := HttpAnalyzer(false, 0)
	err := analyzer.Run(flow)
	assert.NoError(t, err, "Unexpected error")
	assert.Contains(t, flow.Tags, "http", "Expected 'http' tag")
}

func TestHttpAnalyzer_RequestWithCookieFingerprint(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: foo=bar\r\n\r\n")
	flow := &db.FlowEntry{
		Flow: []db.FlowItem{
			{Raw: raw, From: "c"},
		},
	}
	analyzer := HttpAnalyzer(true, 0)
	err := analyzer.Run(flow)
	assert.NoError(t, err, "Unexpected error")
	assert.NotZero(t, len(flow.Fingerprints), "Expected fingerprints from cookies")
}

func TestBodyDecompressor_UnknownEncoding(t *testing.T) {
	r := bytes.NewReader([]byte("test"))
	dec, err := bodyDecompressor(r, "unknown")
	assert.NoError(t, err, "Unexpected error")
	out, _ := io.ReadAll(dec)
	assert.Equal(t, "test", string(out), "Expected passthrough for unknown encoding")
}

func TestHttpAnalyzer_ResponseDeflate(t *testing.T) {
	body := []byte("hello deflate")
	// Deflate is implemented as gzip in bodyDecompressor, so we use gzip here
	deflated := makeGzip(t, body)
	raw := append([]byte("HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n\r\n"), deflated...)
	flow := &db.FlowEntry{
		Flow: []db.FlowItem{{Raw: raw, From: "s"}},
	}
	analyzer := HttpAnalyzer(false, 0)
	err := analyzer.Run(flow)
	assert.NoError(t, err, "Unexpected error")
	assert.Contains(t, flow.Tags, "http", "Expected 'http' tag")
}

func makeGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	buf := bytes.Buffer{}
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err, "Unexpected error writing gzip data")
	w.Close()
	return buf.Bytes()
}

func makeBrotli(t *testing.T, data []byte) []byte {
	t.Helper()
	buf := bytes.Buffer{}
	w := brotli.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err, "Unexpected error writing brotli data")
	w.Close()
	return buf.Bytes()
}
