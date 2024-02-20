// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack_test

import (
	"math"
	"math/rand"
	"testing"

	"github.com/vpnishe/netstack/tcpip"
	"github.com/vpnishe/netstack/tcpip/buffer"
	"github.com/vpnishe/netstack/tcpip/header"
	"github.com/vpnishe/netstack/tcpip/link/channel"
	"github.com/vpnishe/netstack/tcpip/network/ipv4"
	"github.com/vpnishe/netstack/tcpip/network/ipv6"
	"github.com/vpnishe/netstack/tcpip/stack"
	"github.com/vpnishe/netstack/tcpip/transport/udp"
	"github.com/vpnishe/netstack/waiter"
)

const (
	stackV6Addr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	testV6Addr  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"

	stackAddr = "\x0a\x00\x00\x01"
	stackPort = 1234
	testPort  = 4096
)

type testContext struct {
	t       *testing.T
	linkEPs map[string]*channel.Endpoint
	s       *stack.Stack

	ep tcpip.Endpoint
	wq waiter.Queue
}

func (c *testContext) cleanup() {
	if c.ep != nil {
		c.ep.Close()
	}
}

func (c *testContext) createV6Endpoint(v6only bool) {
	var err *tcpip.Error
	c.ep, err = c.s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &c.wq)
	if err != nil {
		c.t.Fatalf("NewEndpoint failed: %v", err)
	}

	var v tcpip.V6OnlyOption
	if v6only {
		v = 1
	}
	if err := c.ep.SetSockOpt(v); err != nil {
		c.t.Fatalf("SetSockOpt failed: %v", err)
	}
}

// newDualTestContextMultiNic creates the testing context and also linkEpNames
// named NICs.
func newDualTestContextMultiNic(t *testing.T, mtu uint32, linkEpNames []string) *testContext {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()}})
	linkEPs := make(map[string]*channel.Endpoint)
	for i, linkEpName := range linkEpNames {
		channelEP := channel.New(256, mtu, "")
		nicID := tcpip.NICID(i + 1)
		if err := s.CreateNamedNIC(nicID, linkEpName, channelEP); err != nil {
			t.Fatalf("CreateNIC failed: %v", err)
		}
		linkEPs[linkEpName] = channelEP

		if err := s.AddAddress(nicID, ipv4.ProtocolNumber, stackAddr); err != nil {
			t.Fatalf("AddAddress IPv4 failed: %v", err)
		}

		if err := s.AddAddress(nicID, ipv6.ProtocolNumber, stackV6Addr); err != nil {
			t.Fatalf("AddAddress IPv6 failed: %v", err)
		}
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         1,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         1,
		},
	})

	return &testContext{
		t:       t,
		s:       s,
		linkEPs: linkEPs,
	}
}

type headers struct {
	srcPort uint16
	dstPort uint16
}

func newPayload() []byte {
	b := make([]byte, 30+rand.Intn(100))
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

func (c *testContext) sendV6Packet(payload []byte, h *headers, linkEpName string) {
	// Allocate a buffer for data and headers.
	buf := buffer.NewView(header.UDPMinimumSize + header.IPv6MinimumSize + len(payload))
	copy(buf[len(buf)-len(payload):], payload)

	// Initialize the IP header.
	ip := header.IPv6(buf)
	ip.Encode(&header.IPv6Fields{
		PayloadLength: uint16(header.UDPMinimumSize + len(payload)),
		NextHeader:    uint8(udp.ProtocolNumber),
		HopLimit:      65,
		SrcAddr:       testV6Addr,
		DstAddr:       stackV6Addr,
	})

	// Initialize the UDP header.
	u := header.UDP(buf[header.IPv6MinimumSize:])
	u.Encode(&header.UDPFields{
		SrcPort: h.srcPort,
		DstPort: h.dstPort,
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})

	// Calculate the UDP pseudo-header checksum.
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, testV6Addr, stackV6Addr, uint16(len(u)))

	// Calculate the UDP checksum and set it.
	xsum = header.Checksum(payload, xsum)
	u.SetChecksum(^u.CalculateChecksum(xsum))

	// Inject packet.
	c.linkEPs[linkEpName].InjectInbound(ipv6.ProtocolNumber, tcpip.PacketBuffer{
		Data: buf.ToVectorisedView(),
	})
}

func TestTransportDemuxerRegister(t *testing.T) {
	for _, test := range []struct {
		name  string
		proto tcpip.NetworkProtocolNumber
		want  *tcpip.Error
	}{
		{"failure", ipv6.ProtocolNumber, tcpip.ErrUnknownProtocol},
		{"success", ipv4.ProtocolNumber, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol()},
				TransportProtocols: []stack.TransportProtocol{udp.NewProtocol()}})
			if got, want := s.RegisterTransportEndpoint(0, []tcpip.NetworkProtocolNumber{test.proto}, udp.ProtocolNumber, stack.TransportEndpointID{}, nil, false, 0), test.want; got != want {
				t.Fatalf("s.RegisterTransportEndpoint(...) = %v, want %v", got, want)
			}
		})
	}
}

// TestReuseBindToDevice injects varied packets on input devices and checks that
// the distribution of packets received matches expectations.
func TestDistribution(t *testing.T) {
	type endpointSockopts struct {
		reuse        int
		bindToDevice string
	}
	for _, test := range []struct {
		name string
		// endpoints will received the inject packets.
		endpoints []endpointSockopts
		// wantedDistribution is the wanted ratio of packets received on each
		// endpoint for each NIC on which packets are injected.
		wantedDistributions map[string][]float64
	}{
		{
			"BindPortReuse",
			// 5 endpoints that all have reuse set.
			[]endpointSockopts{
				endpointSockopts{1, ""},
				endpointSockopts{1, ""},
				endpointSockopts{1, ""},
				endpointSockopts{1, ""},
				endpointSockopts{1, ""},
			},
			map[string][]float64{
				// Injected packets on dev0 get distributed evenly.
				"dev0": []float64{0.2, 0.2, 0.2, 0.2, 0.2},
			},
		},
		{
			"BindToDevice",
			// 3 endpoints with various bindings.
			[]endpointSockopts{
				endpointSockopts{0, "dev0"},
				endpointSockopts{0, "dev1"},
				endpointSockopts{0, "dev2"},
			},
			map[string][]float64{
				// Injected packets on dev0 go only to the endpoint bound to dev0.
				"dev0": []float64{1, 0, 0},
				// Injected packets on dev1 go only to the endpoint bound to dev1.
				"dev1": []float64{0, 1, 0},
				// Injected packets on dev2 go only to the endpoint bound to dev2.
				"dev2": []float64{0, 0, 1},
			},
		},
		{
			"ReuseAndBindToDevice",
			// 6 endpoints with various bindings.
			[]endpointSockopts{
				endpointSockopts{1, "dev0"},
				endpointSockopts{1, "dev0"},
				endpointSockopts{1, "dev1"},
				endpointSockopts{1, "dev1"},
				endpointSockopts{1, "dev1"},
				endpointSockopts{1, ""},
			},
			map[string][]float64{
				// Injected packets on dev0 get distributed among endpoints bound to
				// dev0.
				"dev0": []float64{0.5, 0.5, 0, 0, 0, 0},
				// Injected packets on dev1 get distributed among endpoints bound to
				// dev1 or unbound.
				"dev1": []float64{0, 0, 1. / 3, 1. / 3, 1. / 3, 0},
				// Injected packets on dev999 go only to the unbound.
				"dev999": []float64{0, 0, 0, 0, 0, 1},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for device, wantedDistribution := range test.wantedDistributions {
				t.Run(device, func(t *testing.T) {
					var devices []string
					for d := range test.wantedDistributions {
						devices = append(devices, d)
					}
					c := newDualTestContextMultiNic(t, defaultMTU, devices)
					defer c.cleanup()

					c.createV6Endpoint(false)

					eps := make(map[tcpip.Endpoint]int)

					pollChannel := make(chan tcpip.Endpoint)
					for i, endpoint := range test.endpoints {
						// Try to receive the data.
						wq := waiter.Queue{}
						we, ch := waiter.NewChannelEntry(nil)
						wq.EventRegister(&we, waiter.EventIn)
						defer wq.EventUnregister(&we)
						defer close(ch)

						var err *tcpip.Error
						ep, err := c.s.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
						if err != nil {
							c.t.Fatalf("NewEndpoint failed: %v", err)
						}
						eps[ep] = i

						go func(ep tcpip.Endpoint) {
							for range ch {
								pollChannel <- ep
							}
						}(ep)

						defer ep.Close()
						reusePortOption := tcpip.ReusePortOption(endpoint.reuse)
						if err := ep.SetSockOpt(reusePortOption); err != nil {
							c.t.Fatalf("SetSockOpt(%#v) on endpoint %d failed: %v", reusePortOption, i, err)
						}
						bindToDeviceOption := tcpip.BindToDeviceOption(endpoint.bindToDevice)
						if err := ep.SetSockOpt(bindToDeviceOption); err != nil {
							c.t.Fatalf("SetSockOpt(%#v) on endpoint %d failed: %v", bindToDeviceOption, i, err)
						}
						if err := ep.Bind(tcpip.FullAddress{Addr: stackV6Addr, Port: stackPort}); err != nil {
							t.Fatalf("ep.Bind(...) on endpoint %d failed: %v", i, err)
						}
					}

					npackets := 100000
					nports := 10000
					if got, want := len(test.endpoints), len(wantedDistribution); got != want {
						t.Fatalf("got len(test.endpoints) = %d, want %d", got, want)
					}
					ports := make(map[uint16]tcpip.Endpoint)
					stats := make(map[tcpip.Endpoint]int)
					for i := 0; i < npackets; i++ {
						// Send a packet.
						port := uint16(i % nports)
						payload := newPayload()
						c.sendV6Packet(payload,
							&headers{
								srcPort: testPort + port,
								dstPort: stackPort},
							device)

						var addr tcpip.FullAddress
						ep := <-pollChannel
						_, _, err := ep.Read(&addr)
						if err != nil {
							c.t.Fatalf("Read on endpoint %d failed: %v", eps[ep], err)
						}
						stats[ep]++
						if i < nports {
							ports[uint16(i)] = ep
						} else {
							// Check that all packets from one client are handled by the same
							// socket.
							if want, got := ports[port], ep; want != got {
								t.Fatalf("Packet sent on port %d expected on endpoint %d but received on endpoint %d", port, eps[want], eps[got])
							}
						}
					}

					// Check that a packet distribution is as expected.
					for ep, i := range eps {
						wantedRatio := wantedDistribution[i]
						wantedRecv := wantedRatio * float64(npackets)
						actualRecv := stats[ep]
						actualRatio := float64(stats[ep]) / float64(npackets)
						// The deviation is less than 10%.
						if math.Abs(actualRatio-wantedRatio) > 0.05 {
							t.Errorf("wanted about %.0f%% (%.0f of %d) packets to arrive on endpoint %d, got %.0f%% (%d of %d)", wantedRatio*100, wantedRecv, npackets, i, actualRatio*100, actualRecv, npackets)
						}
					}
				})
			}
		})
	}
}
