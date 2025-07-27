// SPDX-FileCopyrightText: 2022 Qyn <qyn-ctf@gmail.com>
// SPDX-FileCopyrightText: 2022 Rick de Jager <rickdejager99@gmail.com>
// SPDX-FileCopyrightText: 2023 gfelber <34159565+gfelber@users.noreply.github.com>
// SPDX-FileCopyrightText: 2023 liskaant <liskaant@gmail.com>
// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package analysis

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"tulip/pkg/collections"
	"tulip/pkg/db"

	"github.com/andybalholm/brotli"
)

const DefaultDecompressionSize int64 = 10 * 1024 * 1024 // 10 MB

type httpPass struct {
	// If true, we will parse cookies and generate fingerprints
	Experimental bool
	// Maximum size of decompressed body, to prevent decompression bombs.
	// If not set or <= 0, it will default to DefaultDecompressionSize.
	MaxDecompressionSize int64
}

// HttpAnalyzer creates a new HTTP analysis pass.
//
// If experimental is true, it will parse cookies and generate fingerprints.
// If maxDecompressionSize is set to a value greater than 0, it will be used as the
// maximum size of decompressed body else it will default to DefaultDecompressionSize (10 MB).
func HttpAnalyzer(experimental bool, maxDecompressionSize int64) Pass {
	maxSize := DefaultDecompressionSize
	if maxDecompressionSize > 0 {
		maxSize = maxDecompressionSize
	}

	return &httpPass{
		Experimental:         experimental,
		MaxDecompressionSize: maxSize,
	}
}

func (a *httpPass) String() string { return "HTTP Analyzer" }

// Run implements the Analyzer interface for httpAnalyzer.
func (a *httpPass) Run(flow *db.FlowEntry) error {
	// Use a set to get rid of duplicates
	fingerprints := collections.NewSet[uint32]()

	for idx := range flow.Flow {
		a.parseHttpFlowItem(flow, idx, fingerprints)
	}

	if a.Experimental {
		flow.Fingerprints = fingerprints.Items()
	}

	return nil
}

func (a *httpPass) parseHttpFlowItem(flow *db.FlowEntry, idx int, fingerprints collections.Set[uint32]) {
	flowItem := &flow.Flow[idx]
	// TODO; rethink the flowItem format to make this less clunky
	reader := bufio.NewReader(bytes.NewReader(flowItem.Raw))

	switch flowItem.From {
	case "c":
		// HTTP Request
		req, err := http.ReadRequest(reader)
		if err != nil || req == nil {
			return // Failed to fully read the body. Bail out here
		}

		flow.Tags = collections.AppendUnique(flow.Tags, "http")

		if a.Experimental {
			// Parse cookie and grab fingerprints
			fingerprintsFromCookies(&fingerprints, req.Cookies())
		}

		encoding := req.Header.Get("Content-Encoding")
		if len(encoding) == 0 {
			// If we don't find an encoding header, it is either not valid,
			// or already in plain text. In any case, we don't have to edit anything.
			return
		}

		newReader, err := bodyDecompressor(reader, encoding)
		if err != nil || newReader == nil {
			return
		}

		// Replace the reader to allow for in-place decompression
		// Limit the reader to prevent potential decompression bombs
		req.Body = io.NopCloser(io.LimitReader(newReader, a.MaxDecompressionSize))

		// invalidate the content length, since decompressing the body will change its value.
		req.ContentLength = -1

		replacement, err := httputil.DumpRequest(req, true)
		if err != nil {
			// HTTPUtil failed us, continue without replacing anything.
			return
		}

		// This can exceed the mongo document limit, so we need to make sure
		// the replacement will fit
		newSize := flow.Size + (len(replacement) - len(flowItem.Raw))
		if int64(newSize) <= a.MaxDecompressionSize {
			flowItem.Raw = replacement
			flow.Size = newSize
		}

	case "s":
		// HTTP Response
		res, err := http.ReadResponse(reader, nil)
		if err != nil || res == nil {
			return // Failed to fully read the body. Bail out here
		}

		flow.Tags = collections.AppendUnique(flow.Tags, "http")

		if a.Experimental {
			// Parse cookie and grab fingerprints
			fingerprintsFromCookies(&fingerprints, res.Cookies())
		}

		encoding := res.Header.Get("Content-Encoding")
		if len(encoding) == 0 {
			// If we don't find an encoding header, it is either not valid,
			// or already in plain text. In any case, we don't have to edit anything.
			return
		}

		newReader, err := bodyDecompressor(reader, encoding)
		if err != nil || newReader == nil {
			return
		}

		// Replace the reader to allow for in-place decompression
		// Limit the reader to prevent potential decompression bombs
		var maxDecSize = DefaultDecompressionSize
		if a.MaxDecompressionSize > 0 {
			maxDecSize = a.MaxDecompressionSize
		}

		res.Body = io.NopCloser(io.LimitReader(newReader, maxDecSize))

		// invalidate the content length, since decompressing the body will change its value.
		res.ContentLength = -1

		replacement, err := httputil.DumpResponse(res, true)
		if err != nil {
			// HTTPUtil failed us, continue without replacing anything.
			return
		}

		// This can exceed the mongo document limit, so we need to make sure
		// the replacement will fit
		newSize := flow.Size + (len(replacement) - len(flowItem.Raw))
		if int64(newSize) <= a.MaxDecompressionSize {
			flowItem.Raw = replacement
			flow.Size = newSize
		}
	}
}

func fingerprintsFromCookies(set *collections.Set[uint32], cookies []*http.Cookie) {
	for _, cookie := range cookies {
		checksum := cookieFingerprint(cookie)
		set.Add(checksum)
	}
}

func cookieFingerprint(cookie *http.Cookie) uint32 {
	// Prevent exploitation by encoding :pray:, who cares about collisions
	checksum := crc32.Checksum([]byte(url.QueryEscape(cookie.Name)), crc32.IEEETable)
	checksum = crc32.Update(checksum, crc32.IEEETable, []byte("="))
	checksum = crc32.Update(checksum, crc32.IEEETable, []byte(url.QueryEscape(cookie.Value)))
	return checksum
}

func bodyDecompressor(r io.Reader, encoding string) (io.Reader, error) {
	switch strings.ToLower(encoding) {
	case "gzip":
		return gzip.NewReader(r)
	case "br":
		return brotli.NewReader(r), nil
	case "deflate":
		//TODO; verify this is correct
		return gzip.NewReader(r)
	default:
		return r, nil // Unknown or identity encoding
	}
}
