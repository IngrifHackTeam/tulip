// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-only

package assembler

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func makeIPv4Endpoint(ip [4]byte) gopacket.Endpoint {
	return gopacket.NewEndpoint(layers.EndpointIPv4, ip[:])
}

func TestUdpStreamId_Ordering(t *testing.T) {
	epA := makeIPv4Endpoint([4]byte{1, 2, 3, 4})
	epB := makeIPv4Endpoint([4]byte{5, 6, 7, 8})
	portA := layers.UDPPort(1000)
	portB := layers.UDPPort(2000)

	id1 := NewUdpStreamId(epA, epB, portA, portB)
	id2 := NewUdpStreamId(epB, epA, portB, portA)
	id3 := NewUdpStreamId(epA, epB, portB, portA)
	id4 := NewUdpStreamId(epB, epA, portA, portB)

	for _, id := range []UdpStreamId{id1, id2, id3, id4} {
		assert.Equal(t, id1.EndpointLower, epA.FastHash(), "EndpointLower should be the hash of epA")
		assert.Equal(t, id1.EndpointUpper, epB.FastHash(), "EndpointUpper should be the hash of epB")
		assert.Equal(t, id.PortLower, uint16(portA), "PortLower should be the numeric value of portA")
		assert.Equal(t, id.PortUpper, uint16(portB), "PortUpper should be the numeric value of portB")
	}

	for _, id := range []UdpStreamId{id2, id3, id4} {
		assert.Equal(t, id1, id, "Stream IDs should be equal regardless of endpoint and port order")
	}
}

func TestUdpStreamId_EqualEndpointsAndPorts(t *testing.T) {
	ep := makeIPv4Endpoint([4]byte{9, 9, 9, 9})
	port := layers.UDPPort(5555)

	id := NewUdpStreamId(ep, ep, port, port)
	if id.EndpointLower != ep.FastHash() || id.EndpointUpper != ep.FastHash() {
		t.Errorf("Equal endpoints not handled: got (%d, %d), want (%d, %d)", id.EndpointLower, id.EndpointUpper, ep.FastHash(), ep.FastHash())
	}
	if id.PortLower != uint16(port) || id.PortUpper != uint16(port) {
		t.Errorf("Equal ports not handled: got (%d, %d), want (%d, %d)", id.PortLower, id.PortUpper, port, port)
	}
}

func TestUdpStreamId_DifferentEndpointTypes(t *testing.T) {
	// IPv4 vs IPv6 endpoints
	ipv4 := makeIPv4Endpoint([4]byte{1, 2, 3, 4})
	ipv6 := gopacket.NewEndpoint(layers.EndpointIPv6, bytes.Repeat([]byte{0x10}, 16))
	portA := layers.UDPPort(1234)
	portB := layers.UDPPort(4321)

	id := NewUdpStreamId(ipv4, ipv6, portA, portB)
	var lower, upper uint64
	if ipv4.FastHash() < ipv6.FastHash() {
		lower, upper = ipv4.FastHash(), ipv6.FastHash()
	} else {
		lower, upper = ipv6.FastHash(), ipv4.FastHash()
	}
	assert.Equal(t, id.EndpointLower, lower, "EndpointLower should be the lower hash value")
	assert.Equal(t, id.EndpointUpper, upper, "EndpointUpper should be the upper hash value")
}

func TestUdpStreamId_Stability(t *testing.T) {
	epA := makeIPv4Endpoint([4]byte{1, 2, 3, 4})
	epB := makeIPv4Endpoint([4]byte{5, 6, 7, 8})
	portA := layers.UDPPort(1000)
	portB := layers.UDPPort(2000)

	id1 := NewUdpStreamId(epA, epB, portA, portB)
	id2 := NewUdpStreamId(epA, epB, portA, portB)
	id3 := NewUdpStreamId(epA, epB, portA, portB)

	if id1 != id2 || id2 != id3 {
		t.Errorf("Stream ID should be stable across calls: got %+v, %+v, %+v", id1, id2, id3)
	}
}
