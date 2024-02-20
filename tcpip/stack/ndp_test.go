// Copyright 2019 The gVisor Authors.
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
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/vpnishe/netstack/tcpip"
	"github.com/vpnishe/netstack/tcpip/buffer"
	"github.com/vpnishe/netstack/tcpip/checker"
	"github.com/vpnishe/netstack/tcpip/header"
	"github.com/vpnishe/netstack/tcpip/link/channel"
	"github.com/vpnishe/netstack/tcpip/network/ipv6"
	"github.com/vpnishe/netstack/tcpip/stack"
	"github.com/vpnishe/netstack/tcpip/transport/icmp"
)

const (
	addr1          = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
	addr2          = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
	addr3          = "\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"
	linkAddr1      = "\x02\x02\x03\x04\x05\x06"
	linkAddr2      = "\x02\x02\x03\x04\x05\x07"
	linkAddr3      = "\x02\x02\x03\x04\x05\x08"
	defaultTimeout = 250 * time.Millisecond
)

var (
	llAddr1 = header.LinkLocalAddr(linkAddr1)
	llAddr2 = header.LinkLocalAddr(linkAddr2)
	llAddr3 = header.LinkLocalAddr(linkAddr3)
)

// TestDADDisabled tests that an address successfully resolves immediately
// when DAD is not enabled (the default for an empty stack.Options).
func TestDADDisabled(t *testing.T) {
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
	}

	e := channel.New(10, 1280, linkAddr1)
	s := stack.New(opts)
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(_) = %s", err)
	}

	if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
	}

	// Should get the address immediately since we should not have performed
	// DAD on it.
	addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("stack.GetMainNICAddress(_, _) err = %s", err)
	}
	if addr.Address != addr1 {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = %s, want = %s", addr, addr1)
	}

	// We should not have sent any NDP NS messages.
	if got := s.Stats().ICMP.V6PacketsSent.NeighborSolicit.Value(); got != 0 {
		t.Fatalf("got NeighborSolicit = %d, want = 0", got)
	}
}

// ndpDADEvent is a set of parameters that was passed to
// ndpDispatcher.OnDuplicateAddressDetectionStatus.
type ndpDADEvent struct {
	nicID    tcpip.NICID
	addr     tcpip.Address
	resolved bool
	err      *tcpip.Error
}

type ndpRouterEvent struct {
	nicID tcpip.NICID
	addr  tcpip.Address
	// true if router was discovered, false if invalidated.
	discovered bool
}

type ndpPrefixEvent struct {
	nicID  tcpip.NICID
	prefix tcpip.Subnet
	// true if prefix was discovered, false if invalidated.
	discovered bool
}

var _ stack.NDPDispatcher = (*ndpDispatcher)(nil)

// ndpDispatcher implements NDPDispatcher so tests can know when various NDP
// related events happen for test purposes.
type ndpDispatcher struct {
	dadC           chan ndpDADEvent
	routerC        chan ndpRouterEvent
	rememberRouter bool
	prefixC        chan ndpPrefixEvent
	rememberPrefix bool
	routeTable     []tcpip.Route
}

// Implements stack.NDPDispatcher.OnDuplicateAddressDetectionStatus.
func (n *ndpDispatcher) OnDuplicateAddressDetectionStatus(nicID tcpip.NICID, addr tcpip.Address, resolved bool, err *tcpip.Error) {
	if n.dadC != nil {
		n.dadC <- ndpDADEvent{
			nicID,
			addr,
			resolved,
			err,
		}
	}
}

// Implements stack.NDPDispatcher.OnDefaultRouterDiscovered.
func (n *ndpDispatcher) OnDefaultRouterDiscovered(nicID tcpip.NICID, addr tcpip.Address) (bool, []tcpip.Route) {
	if n.routerC != nil {
		n.routerC <- ndpRouterEvent{
			nicID,
			addr,
			true,
		}
	}

	if !n.rememberRouter {
		return false, nil
	}

	rt := append([]tcpip.Route(nil), n.routeTable...)
	rt = append(rt, tcpip.Route{
		Destination: header.IPv6EmptySubnet,
		Gateway:     addr,
		NIC:         nicID,
	})
	n.routeTable = rt
	return true, rt
}

// Implements stack.NDPDispatcher.OnDefaultRouterInvalidated.
func (n *ndpDispatcher) OnDefaultRouterInvalidated(nicID tcpip.NICID, addr tcpip.Address) []tcpip.Route {
	if n.routerC != nil {
		n.routerC <- ndpRouterEvent{
			nicID,
			addr,
			false,
		}
	}

	var rt []tcpip.Route
	exclude := tcpip.Route{
		Destination: header.IPv6EmptySubnet,
		Gateway:     addr,
		NIC:         nicID,
	}

	for _, r := range n.routeTable {
		if r != exclude {
			rt = append(rt, r)
		}
	}
	n.routeTable = rt
	return rt
}

// Implements stack.NDPDispatcher.OnOnLinkPrefixDiscovered.
func (n *ndpDispatcher) OnOnLinkPrefixDiscovered(nicID tcpip.NICID, prefix tcpip.Subnet) (bool, []tcpip.Route) {
	if n.prefixC != nil {
		n.prefixC <- ndpPrefixEvent{
			nicID,
			prefix,
			true,
		}
	}

	if !n.rememberPrefix {
		return false, nil
	}

	rt := append([]tcpip.Route(nil), n.routeTable...)
	rt = append(rt, tcpip.Route{
		Destination: prefix,
		NIC:         nicID,
	})
	n.routeTable = rt
	return true, rt
}

// Implements stack.NDPDispatcher.OnOnLinkPrefixInvalidated.
func (n *ndpDispatcher) OnOnLinkPrefixInvalidated(nicID tcpip.NICID, prefix tcpip.Subnet) []tcpip.Route {
	if n.prefixC != nil {
		n.prefixC <- ndpPrefixEvent{
			nicID,
			prefix,
			false,
		}
	}

	rt := make([]tcpip.Route, 0)
	exclude := tcpip.Route{
		Destination: prefix,
		NIC:         nicID,
	}

	for _, r := range n.routeTable {
		if r != exclude {
			rt = append(rt, r)
		}
	}
	n.routeTable = rt
	return rt
}

// TestDADResolve tests that an address successfully resolves after performing
// DAD for various values of DupAddrDetectTransmits and RetransmitTimer.
// Included in the subtests is a test to make sure that an invalid
// RetransmitTimer (<1ms) values get fixed to the default RetransmitTimer of 1s.
func TestDADResolve(t *testing.T) {
	tests := []struct {
		name                    string
		dupAddrDetectTransmits  uint8
		retransTimer            time.Duration
		expectedRetransmitTimer time.Duration
	}{
		{"1:1s:1s", 1, time.Second, time.Second},
		{"2:1s:1s", 2, time.Second, time.Second},
		{"1:2s:2s", 1, 2 * time.Second, 2 * time.Second},
		// 0s is an invalid RetransmitTimer timer and will be fixed to
		// the default RetransmitTimer value of 1s.
		{"1:0s:1s", 1, 0, time.Second},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent),
			}
			opts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPDisp:          &ndpDisp,
			}
			opts.NDPConfigs.RetransmitTimer = test.retransTimer
			opts.NDPConfigs.DupAddrDetectTransmits = test.dupAddrDetectTransmits

			e := channel.New(10, 1280, linkAddr1)
			s := stack.New(opts)
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
			}

			stat := s.Stats().ICMP.V6PacketsSent.NeighborSolicit

			// Should have sent an NDP NS immediately.
			if got := stat.Value(); got != 1 {
				t.Fatalf("got NeighborSolicit = %d, want = 1", got)

			}

			// Address should not be considered bound to the NIC yet
			// (DAD ongoing).
			addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}

			// Wait for the remaining time - some delta (500ms), to
			// make sure the address is still not resolved.
			const delta = 500 * time.Millisecond
			time.Sleep(test.expectedRetransmitTimer*time.Duration(test.dupAddrDetectTransmits) - delta)
			addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}

			// Wait for DAD to resolve.
			select {
			case <-time.After(2 * delta):
				// We should get a resolution event after 500ms
				// (delta) since we wait for 500ms less than the
				// expected resolution time above to make sure
				// that the address did not yet resolve. Waiting
				// for 1s (2x delta) without a resolution event
				// means something is wrong.
				t.Fatal("timed out waiting for DAD resolution")
			case e := <-ndpDisp.dadC:
				if e.err != nil {
					t.Fatal("got DAD error: ", e.err)
				}
				if e.nicID != 1 {
					t.Fatalf("got DAD event w/ nicID = %d, want = 1", e.nicID)
				}
				if e.addr != addr1 {
					t.Fatalf("got DAD event w/ addr = %s, want = %s", addr, addr1)
				}
				if !e.resolved {
					t.Fatal("got DAD event w/ resolved = false, want = true")
				}
			}
			addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(_, _) err = %s", err)
			}
			if addr.Address != addr1 {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = %s, want = %s", addr, addr1)
			}

			// Should not have sent any more NS messages.
			if got := stat.Value(); got != uint64(test.dupAddrDetectTransmits) {
				t.Fatalf("got NeighborSolicit = %d, want = %d", got, test.dupAddrDetectTransmits)
			}

			// Validate the sent Neighbor Solicitation messages.
			for i := uint8(0); i < test.dupAddrDetectTransmits; i++ {
				p := <-e.C

				// Make sure its an IPv6 packet.
				if p.Proto != header.IPv6ProtocolNumber {
					t.Fatalf("got Proto = %d, want = %d", p.Proto, header.IPv6ProtocolNumber)
				}

				// Check NDP packet.
				checker.IPv6(t, p.Pkt.Header.View().ToVectorisedView().First(),
					checker.TTL(header.NDPHopLimit),
					checker.NDPNS(
						checker.NDPNSTargetAddress(addr1)))
			}
		})
	}

}

// TestDADFail tests to make sure that the DAD process fails if another node is
// detected to be performing DAD on the same address (receive an NS message from
// a node doing DAD for the same address), or if another node is detected to own
// the address already (receive an NA message for the tentative address).
func TestDADFail(t *testing.T) {
	tests := []struct {
		name    string
		makeBuf func(tgt tcpip.Address) buffer.Prependable
		getStat func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter
	}{
		{
			"RxSolicit",
			func(tgt tcpip.Address) buffer.Prependable {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborSolicitMinimumSize)
				pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborSolicitMinimumSize))
				pkt.SetType(header.ICMPv6NeighborSolicit)
				ns := header.NDPNeighborSolicit(pkt.NDPPayload())
				ns.SetTargetAddress(tgt)
				snmc := header.SolicitedNodeAddr(tgt)
				pkt.SetChecksum(header.ICMPv6Checksum(pkt, header.IPv6Any, snmc, buffer.VectorisedView{}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(payloadLength),
					NextHeader:    uint8(icmp.ProtocolNumber6),
					HopLimit:      255,
					SrcAddr:       header.IPv6Any,
					DstAddr:       snmc,
				})

				return hdr

			},
			func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return s.NeighborSolicit
			},
		},
		{
			"RxAdvert",
			func(tgt tcpip.Address) buffer.Prependable {
				hdr := buffer.NewPrependable(header.IPv6MinimumSize + header.ICMPv6NeighborAdvertSize)
				pkt := header.ICMPv6(hdr.Prepend(header.ICMPv6NeighborAdvertSize))
				pkt.SetType(header.ICMPv6NeighborAdvert)
				na := header.NDPNeighborAdvert(pkt.NDPPayload())
				na.SetSolicitedFlag(true)
				na.SetOverrideFlag(true)
				na.SetTargetAddress(tgt)
				pkt.SetChecksum(header.ICMPv6Checksum(pkt, tgt, header.IPv6AllNodesMulticastAddress, buffer.VectorisedView{}))
				payloadLength := hdr.UsedLength()
				ip := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
				ip.Encode(&header.IPv6Fields{
					PayloadLength: uint16(payloadLength),
					NextHeader:    uint8(icmp.ProtocolNumber6),
					HopLimit:      255,
					SrcAddr:       tgt,
					DstAddr:       header.IPv6AllNodesMulticastAddress,
				})

				return hdr

			},
			func(s tcpip.ICMPv6ReceivedPacketStats) *tcpip.StatCounter {
				return s.NeighborAdvert
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent),
			}
			ndpConfigs := stack.DefaultNDPConfigurations()
			opts := stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs:       ndpConfigs,
				NDPDisp:          &ndpDisp,
			}
			opts.NDPConfigs.RetransmitTimer = time.Second * 2

			e := channel.New(10, 1280, linkAddr1)
			s := stack.New(opts)
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(_) = %s", err)
			}

			if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
			}

			// Address should not be considered bound to the NIC yet
			// (DAD ongoing).
			addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}

			// Receive a packet to simulate multiple nodes owning or
			// attempting to own the same address.
			hdr := test.makeBuf(addr1)
			e.InjectInbound(header.IPv6ProtocolNumber, tcpip.PacketBuffer{
				Data: hdr.View().ToVectorisedView(),
			})

			stat := test.getStat(s.Stats().ICMP.V6PacketsReceived)
			if got := stat.Value(); got != 1 {
				t.Fatalf("got stat = %d, want = 1", got)
			}

			// Wait for DAD to fail and make sure the address did
			// not get resolved.
			select {
			case <-time.After(time.Duration(ndpConfigs.DupAddrDetectTransmits)*ndpConfigs.RetransmitTimer + time.Second):
				// If we don't get a failure event after the
				// expected resolution time + extra 1s buffer,
				// something is wrong.
				t.Fatal("timed out waiting for DAD failure")
			case e := <-ndpDisp.dadC:
				if e.err != nil {
					t.Fatal("got DAD error: ", e.err)
				}
				if e.nicID != 1 {
					t.Fatalf("got DAD event w/ nicID = %d, want = 1", e.nicID)
				}
				if e.addr != addr1 {
					t.Fatalf("got DAD event w/ addr = %s, want = %s", addr, addr1)
				}
				if e.resolved {
					t.Fatal("got DAD event w/ resolved = true, want = false")
				}
			}
			addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}
		})
	}
}

// TestDADStop tests to make sure that the DAD process stops when an address is
// removed.
func TestDADStop(t *testing.T) {
	ndpDisp := ndpDispatcher{
		dadC: make(chan ndpDADEvent),
	}
	ndpConfigs := stack.NDPConfigurations{
		RetransmitTimer:        time.Second,
		DupAddrDetectTransmits: 2,
	}
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPDisp:          &ndpDisp,
		NDPConfigs:       ndpConfigs,
	}

	e := channel.New(10, 1280, linkAddr1)
	s := stack.New(opts)
	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(_) = %s", err)
	}

	if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
		t.Fatalf("AddAddress(_, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
	}

	// Address should not be considered bound to the NIC yet (DAD ongoing).
	addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
	}
	if want := (tcpip.AddressWithPrefix{}); addr != want {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
	}

	// Remove the address. This should stop DAD.
	if err := s.RemoveAddress(1, addr1); err != nil {
		t.Fatalf("RemoveAddress(_, %s) = %s", addr1, err)
	}

	// Wait for DAD to fail (since the address was removed during DAD).
	select {
	case <-time.After(time.Duration(ndpConfigs.DupAddrDetectTransmits)*ndpConfigs.RetransmitTimer + time.Second):
		// If we don't get a failure event after the expected resolution
		// time + extra 1s buffer, something is wrong.
		t.Fatal("timed out waiting for DAD failure")
	case e := <-ndpDisp.dadC:
		if e.err != nil {
			t.Fatal("got DAD error: ", e.err)
		}
		if e.nicID != 1 {
			t.Fatalf("got DAD event w/ nicID = %d, want = 1", e.nicID)
		}
		if e.addr != addr1 {
			t.Fatalf("got DAD event w/ addr = %s, want = %s", addr, addr1)
		}
		if e.resolved {
			t.Fatal("got DAD event w/ resolved = true, want = false")
		}

	}
	addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
	if err != nil {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
	}
	if want := (tcpip.AddressWithPrefix{}); addr != want {
		t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
	}

	// Should not have sent more than 1 NS message.
	if got := s.Stats().ICMP.V6PacketsSent.NeighborSolicit.Value(); got > 1 {
		t.Fatalf("got NeighborSolicit = %d, want <= 1", got)
	}
}

// TestSetNDPConfigurationFailsForBadNICID tests to make sure we get an error if
// we attempt to update NDP configurations using an invalid NICID.
func TestSetNDPConfigurationFailsForBadNICID(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
	})

	// No NIC with ID 1 yet.
	if got := s.SetNDPConfigurations(1, stack.NDPConfigurations{}); got != tcpip.ErrUnknownNICID {
		t.Fatalf("got s.SetNDPConfigurations = %v, want = %s", got, tcpip.ErrUnknownNICID)
	}
}

// TestSetNDPConfigurations tests that we can update and use per-interface NDP
// configurations without affecting the default NDP configurations or other
// interfaces' configurations.
func TestSetNDPConfigurations(t *testing.T) {
	tests := []struct {
		name                    string
		dupAddrDetectTransmits  uint8
		retransmitTimer         time.Duration
		expectedRetransmitTimer time.Duration
	}{
		{
			"OK",
			1,
			time.Second,
			time.Second,
		},
		{
			"Invalid Retransmit Timer",
			1,
			0,
			time.Second,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				dadC: make(chan ndpDADEvent),
			}
			e := channel.New(10, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPDisp:          &ndpDisp,
			})

			// This NIC(1)'s NDP configurations will be updated to
			// be different from the default.
			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Created before updating NIC(1)'s NDP configurations
			// but updating NIC(1)'s NDP configurations should not
			// affect other existing NICs.
			if err := s.CreateNIC(2, e); err != nil {
				t.Fatalf("CreateNIC(2) = %s", err)
			}

			// Update the NDP configurations on NIC(1) to use DAD.
			configs := stack.NDPConfigurations{
				DupAddrDetectTransmits: test.dupAddrDetectTransmits,
				RetransmitTimer:        test.retransmitTimer,
			}
			if err := s.SetNDPConfigurations(1, configs); err != nil {
				t.Fatalf("got SetNDPConfigurations(1, _) = %s", err)
			}

			// Created after updating NIC(1)'s NDP configurations
			// but the stack's default NDP configurations should not
			// have been updated.
			if err := s.CreateNIC(3, e); err != nil {
				t.Fatalf("CreateNIC(3) = %s", err)
			}

			// Add addresses for each NIC.
			if err := s.AddAddress(1, header.IPv6ProtocolNumber, addr1); err != nil {
				t.Fatalf("AddAddress(1, %d, %s) = %s", header.IPv6ProtocolNumber, addr1, err)
			}
			if err := s.AddAddress(2, header.IPv6ProtocolNumber, addr2); err != nil {
				t.Fatalf("AddAddress(2, %d, %s) = %s", header.IPv6ProtocolNumber, addr2, err)
			}
			if err := s.AddAddress(3, header.IPv6ProtocolNumber, addr3); err != nil {
				t.Fatalf("AddAddress(3, %d, %s) = %s", header.IPv6ProtocolNumber, addr3, err)
			}

			// Address should not be considered bound to NIC(1) yet
			// (DAD ongoing).
			addr, err := s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}

			// Should get the address on NIC(2) and NIC(3)
			// immediately since we should not have performed DAD on
			// it as the stack was configured to not do DAD by
			// default and we only updated the NDP configurations on
			// NIC(1).
			addr, err = s.GetMainNICAddress(2, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(2, _) err = %s", err)
			}
			if addr.Address != addr2 {
				t.Fatalf("got stack.GetMainNICAddress(2, _) = %s, want = %s", addr, addr2)
			}
			addr, err = s.GetMainNICAddress(3, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(3, _) err = %s", err)
			}
			if addr.Address != addr3 {
				t.Fatalf("got stack.GetMainNICAddress(3, _) = %s, want = %s", addr, addr3)
			}

			// Sleep until right (500ms before) before resolution to
			// make sure the address didn't resolve on NIC(1) yet.
			const delta = 500 * time.Millisecond
			time.Sleep(time.Duration(test.dupAddrDetectTransmits)*test.expectedRetransmitTimer - delta)
			addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (_, %v), want = (_, nil)", err)
			}
			if want := (tcpip.AddressWithPrefix{}); addr != want {
				t.Fatalf("got stack.GetMainNICAddress(_, _) = (%s, nil), want = (%s, nil)", addr, want)
			}

			// Wait for DAD to resolve.
			select {
			case <-time.After(2 * delta):
				// We should get a resolution event after 500ms
				// (delta) since we wait for 500ms less than the
				// expected resolution time above to make sure
				// that the address did not yet resolve. Waiting
				// for 1s (2x delta) without a resolution event
				// means something is wrong.
				t.Fatal("timed out waiting for DAD resolution")
			case e := <-ndpDisp.dadC:
				if e.err != nil {
					t.Fatal("got DAD error: ", e.err)
				}
				if e.nicID != 1 {
					t.Fatalf("got DAD event w/ nicID = %d, want = 1", e.nicID)
				}
				if e.addr != addr1 {
					t.Fatalf("got DAD event w/ addr = %s, want = %s", addr, addr1)
				}
				if !e.resolved {
					t.Fatal("got DAD event w/ resolved = false, want = true")
				}
			}
			addr, err = s.GetMainNICAddress(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("stack.GetMainNICAddress(1, _) err = %s", err)
			}
			if addr.Address != addr1 {
				t.Fatalf("got stack.GetMainNICAddress(1, _) = %s, want = %s", addr, addr1)
			}
		})
	}
}

// raBufWithOpts returns a valid NDP Router Advertisement with options.
//
// Note, raBufWithOpts does not populate any of the RA fields other than the
// Router Lifetime.
func raBufWithOpts(ip tcpip.Address, rl uint16, optSer header.NDPOptionsSerializer) tcpip.PacketBuffer {
	icmpSize := header.ICMPv6HeaderSize + header.NDPRAMinimumSize + int(optSer.Length())
	hdr := buffer.NewPrependable(header.IPv6MinimumSize + icmpSize)
	pkt := header.ICMPv6(hdr.Prepend(icmpSize))
	pkt.SetType(header.ICMPv6RouterAdvert)
	pkt.SetCode(0)
	ra := header.NDPRouterAdvert(pkt.NDPPayload())
	opts := ra.Options()
	opts.Serialize(optSer)
	// Populate the Router Lifetime.
	binary.BigEndian.PutUint16(pkt.NDPPayload()[2:], rl)
	pkt.SetChecksum(header.ICMPv6Checksum(pkt, ip, header.IPv6AllNodesMulticastAddress, buffer.VectorisedView{}))
	payloadLength := hdr.UsedLength()
	iph := header.IPv6(hdr.Prepend(header.IPv6MinimumSize))
	iph.Encode(&header.IPv6Fields{
		PayloadLength: uint16(payloadLength),
		NextHeader:    uint8(icmp.ProtocolNumber6),
		HopLimit:      header.NDPHopLimit,
		SrcAddr:       ip,
		DstAddr:       header.IPv6AllNodesMulticastAddress,
	})

	return tcpip.PacketBuffer{Data: hdr.View().ToVectorisedView()}
}

// raBuf returns a valid NDP Router Advertisement.
//
// Note, raBuf does not populate any of the RA fields other than the
// Router Lifetime.
func raBuf(ip tcpip.Address, rl uint16) tcpip.PacketBuffer {
	return raBufWithOpts(ip, rl, header.NDPOptionsSerializer{})
}

// raBufWithPI returns a valid NDP Router Advertisement with a single Prefix
// Information option.
//
// Note, raBufWithPI does not populate any of the RA fields other than the
// Router Lifetime.
func raBufWithPI(ip tcpip.Address, rl uint16, prefix tcpip.AddressWithPrefix, onLink bool, vl uint32) tcpip.PacketBuffer {
	flags := uint8(0)
	if onLink {
		flags |= 128
	}

	buf := [30]byte{}
	buf[0] = uint8(prefix.PrefixLen)
	buf[1] = flags
	binary.BigEndian.PutUint32(buf[2:], vl)
	copy(buf[14:], prefix.Address)
	return raBufWithOpts(ip, rl, header.NDPOptionsSerializer{
		header.NDPPrefixInformation(buf[:]),
	})
}

// TestNoRouterDiscovery tests that router discovery will not be performed if
// configured not to.
func TestNoRouterDiscovery(t *testing.T) {
	// Being configured to discover routers means handle and
	// discover are set to true and forwarding is set to false.
	// This tests all possible combinations of the configurations,
	// except for the configuration where handle = true, discover =
	// true and forwarding = false (the required configuration to do
	// router discovery) - that will done in other tests.
	for i := 0; i < 7; i++ {
		handle := i&1 != 0
		discover := i&2 != 0
		forwarding := i&4 == 0

		t.Run(fmt.Sprintf("HandleRAs(%t), DiscoverDefaultRouters(%t), Forwarding(%t)", handle, discover, forwarding), func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				routerC: make(chan ndpRouterEvent, 10),
			}
			e := channel.New(10, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs:              handle,
					DiscoverDefaultRouters: discover,
				},
				NDPDisp: &ndpDisp,
			})
			s.SetForwarding(forwarding)

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Rx an RA with non-zero lifetime.
			e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 1000))
			select {
			case <-ndpDisp.routerC:
				t.Fatal("unexpectedly discovered a router when configured not to")
			case <-time.After(defaultTimeout):
			}
		})
	}
}

// TestRouterDiscoveryDispatcherNoRemember tests that the stack does not
// remember a discovered router when the dispatcher asks it not to.
func TestRouterDiscoveryDispatcherNoRemember(t *testing.T) {
	ndpDisp := ndpDispatcher{
		routerC: make(chan ndpRouterEvent, 10),
	}
	e := channel.New(10, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	routeTable := []tcpip.Route{
		{
			header.IPv6EmptySubnet,
			llAddr3,
			1,
		},
	}
	s.SetRouteTable(routeTable)

	// Rx an RA with short lifetime.
	lifetime := time.Duration(1)
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, uint16(lifetime)))
	select {
	case r := <-ndpDisp.routerC:
		if r.nicID != 1 {
			t.Fatalf("got r.nicID = %d, want = 1", r.nicID)
		}
		if r.addr != llAddr2 {
			t.Fatalf("got r.addr = %s, want = %s", r.addr, llAddr2)
		}
		if !r.discovered {
			t.Fatal("got r.discovered = false, want = true")
		}
	case <-time.After(defaultTimeout):
		t.Fatal("timeout waiting for router discovery event")
	}

	// Original route table should not have been modified.
	if got := s.GetRouteTable(); !cmp.Equal(got, routeTable) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, routeTable)
	}

	// Wait for the normal invalidation time plus an extra second to
	// make sure we do not actually receive any invalidation events as
	// we should not have remembered the router in the first place.
	select {
	case <-ndpDisp.routerC:
		t.Fatal("should not have received any router events")
	case <-time.After(lifetime*time.Second + defaultTimeout):
	}

	// Original route table should not have been modified.
	if got := s.GetRouteTable(); !cmp.Equal(got, routeTable) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, routeTable)
	}
}

func TestRouterDiscovery(t *testing.T) {
	ndpDisp := ndpDispatcher{
		routerC:        make(chan ndpRouterEvent, 10),
		rememberRouter: true,
	}
	e := channel.New(10, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: true,
		},
		NDPDisp: &ndpDisp,
	})

	waitForEvent := func(addr tcpip.Address, discovered bool, timeout time.Duration) {
		t.Helper()

		select {
		case r := <-ndpDisp.routerC:
			if r.nicID != 1 {
				t.Fatalf("got r.nicID = %d, want = 1", r.nicID)
			}
			if r.addr != addr {
				t.Fatalf("got r.addr = %s, want = %s", r.addr, addr)
			}
			if r.discovered != discovered {
				t.Fatalf("got r.discovered = %t, want = %t", r.discovered, discovered)
			}
		case <-time.After(timeout):
			t.Fatal("timeout waiting for router discovery event")
		}
	}

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Rx an RA from lladdr2 with zero lifetime. It should not be
	// remembered.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 0))
	select {
	case <-ndpDisp.routerC:
		t.Fatal("unexpectedly discovered a router with 0 lifetime")
	case <-time.After(defaultTimeout):
	}

	// Rx an RA from lladdr2 with a huge lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 1000))
	waitForEvent(llAddr2, true, defaultTimeout)

	// Should have a default route through the discovered router.
	if got, want := s.GetRouteTable(), []tcpip.Route{{header.IPv6EmptySubnet, llAddr2, 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Rx an RA from another router (lladdr3) with non-zero lifetime.
	l3Lifetime := time.Duration(6)
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr3, uint16(l3Lifetime)))
	waitForEvent(llAddr3, true, defaultTimeout)

	// Should have default routes through the discovered routers.
	if got, want := s.GetRouteTable(), []tcpip.Route{{header.IPv6EmptySubnet, llAddr2, 1}, {header.IPv6EmptySubnet, llAddr3, 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Rx an RA from lladdr2 with lesser lifetime.
	l2Lifetime := time.Duration(2)
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, uint16(l2Lifetime)))
	select {
	case <-ndpDisp.routerC:
		t.Fatal("Should not receive a router event when updating lifetimes for known routers")
	case <-time.After(defaultTimeout):
	}

	// Should still have a default route through the discovered routers.
	if got, want := s.GetRouteTable(), []tcpip.Route{{header.IPv6EmptySubnet, llAddr2, 1}, {header.IPv6EmptySubnet, llAddr3, 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Wait for lladdr2's router invalidation timer to fire. The lifetime
	// of the router should have been updated to the most recent (smaller)
	// lifetime.
	//
	// Wait for the normal lifetime plus an extra bit for the
	// router to get invalidated. If we don't get an invalidation
	// event after this time, then something is wrong.
	waitForEvent(llAddr2, false, l2Lifetime*time.Second+defaultTimeout)

	// Should no longer have the default route through lladdr2.
	if got, want := s.GetRouteTable(), []tcpip.Route{{header.IPv6EmptySubnet, llAddr3, 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Rx an RA from lladdr2 with huge lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 1000))
	waitForEvent(llAddr2, true, defaultTimeout)

	// Should have a default route through the discovered routers.
	if got, want := s.GetRouteTable(), []tcpip.Route{{header.IPv6EmptySubnet, llAddr3, 1}, {header.IPv6EmptySubnet, llAddr2, 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Rx an RA from lladdr2 with zero lifetime. It should be invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr2, 0))
	waitForEvent(llAddr2, false, defaultTimeout)

	// Should have deleted the default route through the router that just
	// got invalidated.
	if got, want := s.GetRouteTable(), []tcpip.Route{{header.IPv6EmptySubnet, llAddr3, 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Wait for lladdr3's router invalidation timer to fire. The lifetime
	// of the router should have been updated to the most recent (smaller)
	// lifetime.
	//
	// Wait for the normal lifetime plus an extra bit for the
	// router to get invalidated. If we don't get an invalidation
	// event after this time, then something is wrong.
	waitForEvent(llAddr3, false, l3Lifetime*time.Second+defaultTimeout)

	// Should not have any routes now that all discovered routers have been
	// invalidated.
	if got := len(s.GetRouteTable()); got != 0 {
		t.Fatalf("got len(s.GetRouteTable()) = %d, want = 0", got)
	}
}

// TestRouterDiscoveryMaxRouters tests that only
// stack.MaxDiscoveredDefaultRouters discovered routers are remembered.
func TestRouterDiscoveryMaxRouters(t *testing.T) {
	ndpDisp := ndpDispatcher{
		routerC:        make(chan ndpRouterEvent, 10),
		rememberRouter: true,
	}
	e := channel.New(10, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	expectedRt := [stack.MaxDiscoveredDefaultRouters]tcpip.Route{}

	// Receive an RA from 2 more than the max number of discovered routers.
	for i := 1; i <= stack.MaxDiscoveredDefaultRouters+2; i++ {
		linkAddr := []byte{2, 2, 3, 4, 5, 0}
		linkAddr[5] = byte(i)
		llAddr := header.LinkLocalAddr(tcpip.LinkAddress(linkAddr))

		e.InjectInbound(header.IPv6ProtocolNumber, raBuf(llAddr, 5))

		if i <= stack.MaxDiscoveredDefaultRouters {
			expectedRt[i-1] = tcpip.Route{header.IPv6EmptySubnet, llAddr, 1}
			select {
			case r := <-ndpDisp.routerC:
				if r.nicID != 1 {
					t.Fatalf("got r.nicID = %d, want = 1", r.nicID)
				}
				if r.addr != llAddr {
					t.Fatalf("got r.addr = %s, want = %s", r.addr, llAddr)
				}
				if !r.discovered {
					t.Fatal("got r.discovered = false, want = true")
				}
			case <-time.After(defaultTimeout):
				t.Fatal("timeout waiting for router discovery event")
			}

		} else {
			select {
			case <-ndpDisp.routerC:
				t.Fatal("should not have discovered a new router after we already discovered the max number of routers")
			case <-time.After(defaultTimeout):
			}
		}
	}

	// Should only have default routes for the first
	// stack.MaxDiscoveredDefaultRouters discovered routers.
	if got := s.GetRouteTable(); !cmp.Equal(got, expectedRt[:]) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, expectedRt)
	}
}

// TestNoPrefixDiscovery tests that prefix discovery will not be performed if
// configured not to.
func TestNoPrefixDiscovery(t *testing.T) {
	prefix := tcpip.AddressWithPrefix{
		Address:   tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		PrefixLen: 64,
	}

	// Being configured to discover prefixes means handle and
	// discover are set to true and forwarding is set to false.
	// This tests all possible combinations of the configurations,
	// except for the configuration where handle = true, discover =
	// true and forwarding = false (the required configuration to do
	// prefix discovery) - that will done in other tests.
	for i := 0; i < 7; i++ {
		handle := i&1 != 0
		discover := i&2 != 0
		forwarding := i&4 == 0

		t.Run(fmt.Sprintf("HandleRAs(%t), DiscoverOnLinkPrefixes(%t), Forwarding(%t)", handle, discover, forwarding), func(t *testing.T) {
			ndpDisp := ndpDispatcher{
				prefixC: make(chan ndpPrefixEvent, 10),
			}
			e := channel.New(10, 1280, linkAddr1)
			s := stack.New(stack.Options{
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NDPConfigs: stack.NDPConfigurations{
					HandleRAs:              handle,
					DiscoverOnLinkPrefixes: discover,
				},
				NDPDisp: &ndpDisp,
			})
			s.SetForwarding(forwarding)

			if err := s.CreateNIC(1, e); err != nil {
				t.Fatalf("CreateNIC(1) = %s", err)
			}

			// Rx an RA with prefix with non-zero lifetime.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, 10))

			select {
			case <-ndpDisp.prefixC:
				t.Fatal("unexpectedly discovered a prefix when configured not to")
			case <-time.After(defaultTimeout):
			}
		})
	}
}

// TestPrefixDiscoveryDispatcherNoRemember tests that the stack does not
// remember a discovered on-link prefix when the dispatcher asks it not to.
func TestPrefixDiscoveryDispatcherNoRemember(t *testing.T) {
	prefix := tcpip.AddressWithPrefix{
		Address:   tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		PrefixLen: 64,
	}
	subnet := prefix.Subnet()

	ndpDisp := ndpDispatcher{
		prefixC: make(chan ndpPrefixEvent, 10),
	}
	e := channel.New(10, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: false,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	routeTable := []tcpip.Route{
		{
			header.IPv6EmptySubnet,
			llAddr3,
			1,
		},
	}
	s.SetRouteTable(routeTable)

	// Rx an RA with prefix with a short lifetime.
	const lifetime = 1
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, lifetime))
	select {
	case r := <-ndpDisp.prefixC:
		if r.nicID != 1 {
			t.Fatalf("got r.nicID = %d, want = 1", r.nicID)
		}
		if r.prefix != subnet {
			t.Fatalf("got r.prefix = %s, want = %s", r.prefix, subnet)
		}
		if !r.discovered {
			t.Fatal("got r.discovered = false, want = true")
		}
	case <-time.After(defaultTimeout):
		t.Fatal("timeout waiting for prefix discovery event")
	}

	// Original route table should not have been modified.
	if got := s.GetRouteTable(); !cmp.Equal(got, routeTable) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, routeTable)
	}

	// Wait for the normal invalidation time plus some buffer to
	// make sure we do not actually receive any invalidation events as
	// we should not have remembered the prefix in the first place.
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("should not have received any prefix events")
	case <-time.After(lifetime*time.Second + defaultTimeout):
	}

	// Original route table should not have been modified.
	if got := s.GetRouteTable(); !cmp.Equal(got, routeTable) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, routeTable)
	}
}

func TestPrefixDiscovery(t *testing.T) {
	prefix1 := tcpip.AddressWithPrefix{
		Address:   tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		PrefixLen: 64,
	}
	prefix2 := tcpip.AddressWithPrefix{
		Address:   tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x09\x00\x00\x00\x00\x00\x00\x00\x00"),
		PrefixLen: 64,
	}
	prefix3 := tcpip.AddressWithPrefix{
		Address:   tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x09\x0a\x00\x00\x00\x00\x00\x00\x00"),
		PrefixLen: 72,
	}
	subnet1 := prefix1.Subnet()
	subnet2 := prefix2.Subnet()
	subnet3 := prefix3.Subnet()

	ndpDisp := ndpDispatcher{
		prefixC:        make(chan ndpPrefixEvent, 10),
		rememberPrefix: true,
	}
	e := channel.New(10, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	waitForEvent := func(subnet tcpip.Subnet, discovered bool, timeout time.Duration) {
		t.Helper()

		select {
		case r := <-ndpDisp.prefixC:
			if r.nicID != 1 {
				t.Fatalf("got r.nicID = %d, want = 1", r.nicID)
			}
			if r.prefix != subnet {
				t.Fatalf("got r.prefix = %s, want = %s", r.prefix, subnet)
			}
			if r.discovered != discovered {
				t.Fatalf("got r.discovered = %t, want = %t", r.discovered, discovered)
			}
		case <-time.After(timeout):
			t.Fatal("timeout waiting for prefix discovery event")
		}
	}

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with zero valid lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, 0))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly discovered a prefix with 0 lifetime")
	case <-time.After(defaultTimeout):
	}

	// Receive an RA with prefix1 in an NDP Prefix Information option (PI)
	// with non-zero lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, 100))
	waitForEvent(subnet1, true, defaultTimeout)

	// Should have added a device route for subnet1 through the nic.
	if got, want := s.GetRouteTable(), []tcpip.Route{{subnet1, tcpip.Address([]byte(nil)), 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Receive an RA with prefix2 in a PI.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, 100))
	waitForEvent(subnet2, true, defaultTimeout)

	// Should have added a device route for subnet2 through the nic.
	if got, want := s.GetRouteTable(), []tcpip.Route{{subnet1, tcpip.Address([]byte(nil)), 1}, {subnet2, tcpip.Address([]byte(nil)), 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Receive an RA with prefix3 in a PI.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix3, true, 100))
	waitForEvent(subnet3, true, defaultTimeout)

	// Should have added a device route for subnet3 through the nic.
	if got, want := s.GetRouteTable(), []tcpip.Route{{subnet1, tcpip.Address([]byte(nil)), 1}, {subnet2, tcpip.Address([]byte(nil)), 1}, {subnet3, tcpip.Address([]byte(nil)), 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Receive an RA with prefix1 in a PI with lifetime = 0.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix1, true, 0))
	waitForEvent(subnet1, false, defaultTimeout)

	// Should have removed the device route for subnet1 through the nic.
	if got, want := s.GetRouteTable(), []tcpip.Route{{subnet2, tcpip.Address([]byte(nil)), 1}, {subnet3, tcpip.Address([]byte(nil)), 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Receive an RA with prefix2 in a PI with lesser lifetime.
	lifetime := uint32(2)
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix2, true, lifetime))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly received prefix event when updating lifetime")
	case <-time.After(defaultTimeout):
	}

	// Should not have updated route table.
	if got, want := s.GetRouteTable(), []tcpip.Route{{subnet2, tcpip.Address([]byte(nil)), 1}, {subnet3, tcpip.Address([]byte(nil)), 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Wait for prefix2's most recent invalidation timer plus some buffer to
	// expire.
	waitForEvent(subnet2, false, time.Duration(lifetime)*time.Second+defaultTimeout)

	// Should have removed the device route for subnet2 through the nic.
	if got, want := s.GetRouteTable(), []tcpip.Route{{subnet3, tcpip.Address([]byte(nil)), 1}}; !cmp.Equal(got, want) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, want)
	}

	// Receive RA to invalidate prefix3.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix3, true, 0))
	waitForEvent(subnet3, false, defaultTimeout)

	// Should not have any routes.
	if got := len(s.GetRouteTable()); got != 0 {
		t.Fatalf("got len(s.GetRouteTable()) = %d, want = 0", got)
	}
}

func TestPrefixDiscoveryWithInfiniteLifetime(t *testing.T) {
	// Update the infinite lifetime value to a smaller value so we can test
	// that when we receive a PI with such a lifetime value, we do not
	// invalidate the prefix.
	const testInfiniteLifetimeSeconds = 2
	const testInfiniteLifetime = testInfiniteLifetimeSeconds * time.Second
	saved := header.NDPPrefixInformationInfiniteLifetime
	header.NDPPrefixInformationInfiniteLifetime = testInfiniteLifetime
	defer func() {
		header.NDPPrefixInformationInfiniteLifetime = saved
	}()

	prefix := tcpip.AddressWithPrefix{
		Address:   tcpip.Address("\x01\x02\x03\x04\x05\x06\x07\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		PrefixLen: 64,
	}
	subnet := prefix.Subnet()

	ndpDisp := ndpDispatcher{
		prefixC:        make(chan ndpPrefixEvent, 10),
		rememberPrefix: true,
	}
	e := channel.New(10, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	waitForEvent := func(discovered bool, timeout time.Duration) {
		t.Helper()

		select {
		case r := <-ndpDisp.prefixC:
			if r.nicID != 1 {
				t.Errorf("got r.nicID = %d, want = 1", r.nicID)
			}
			if r.prefix != subnet {
				t.Errorf("got r.prefix = %s, want = %s", r.prefix, subnet)
			}
			if r.discovered != discovered {
				t.Errorf("got r.discovered = %t, want = %t", r.discovered, discovered)
			}
		case <-time.After(timeout):
			t.Fatal("timeout waiting for prefix discovery event")
		}
	}

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	// Receive an RA with prefix in an NDP Prefix Information option (PI)
	// with infinite valid lifetime which should not get invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, testInfiniteLifetimeSeconds))
	waitForEvent(true, defaultTimeout)
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	case <-time.After(testInfiniteLifetime + defaultTimeout):
	}

	// Receive an RA with finite lifetime.
	// The prefix should get invalidated after 1s.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, testInfiniteLifetimeSeconds-1))
	waitForEvent(false, testInfiniteLifetime)

	// Receive an RA with finite lifetime.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, testInfiniteLifetimeSeconds-1))
	waitForEvent(true, defaultTimeout)

	// Receive an RA with prefix with an infinite lifetime.
	// The prefix should not be invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, testInfiniteLifetimeSeconds))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	case <-time.After(testInfiniteLifetime + defaultTimeout):
	}

	// Receive an RA with a prefix with a lifetime value greater than the
	// set infinite lifetime value.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, testInfiniteLifetimeSeconds+1))
	select {
	case <-ndpDisp.prefixC:
		t.Fatal("unexpectedly invalidated a prefix with infinite lifetime")
	case <-time.After((testInfiniteLifetimeSeconds+1)*time.Second + defaultTimeout):
	}

	// Receive an RA with 0 lifetime.
	// The prefix should get invalidated.
	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, true, 0))
	waitForEvent(false, defaultTimeout)
}

// TestPrefixDiscoveryMaxRouters tests that only
// stack.MaxDiscoveredOnLinkPrefixes discovered on-link prefixes are remembered.
func TestPrefixDiscoveryMaxOnLinkPrefixes(t *testing.T) {
	ndpDisp := ndpDispatcher{
		prefixC:        make(chan ndpPrefixEvent, stack.MaxDiscoveredOnLinkPrefixes+3),
		rememberPrefix: true,
	}
	e := channel.New(10, 1280, linkAddr1)
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NDPConfigs: stack.NDPConfigurations{
			HandleRAs:              true,
			DiscoverDefaultRouters: false,
			DiscoverOnLinkPrefixes: true,
		},
		NDPDisp: &ndpDisp,
	})

	if err := s.CreateNIC(1, e); err != nil {
		t.Fatalf("CreateNIC(1) = %s", err)
	}

	optSer := make(header.NDPOptionsSerializer, stack.MaxDiscoveredOnLinkPrefixes+2)
	expectedRt := [stack.MaxDiscoveredOnLinkPrefixes]tcpip.Route{}
	prefixes := [stack.MaxDiscoveredOnLinkPrefixes + 2]tcpip.Subnet{}

	// Receive an RA with 2 more than the max number of discovered on-link
	// prefixes.
	for i := 0; i < stack.MaxDiscoveredOnLinkPrefixes+2; i++ {
		prefixAddr := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}
		prefixAddr[7] = byte(i)
		prefix := tcpip.AddressWithPrefix{
			Address:   tcpip.Address(prefixAddr[:]),
			PrefixLen: 64,
		}
		prefixes[i] = prefix.Subnet()
		buf := [30]byte{}
		buf[0] = uint8(prefix.PrefixLen)
		buf[1] = 128
		binary.BigEndian.PutUint32(buf[2:], 10)
		copy(buf[14:], prefix.Address)

		optSer[i] = header.NDPPrefixInformation(buf[:])

		if i < stack.MaxDiscoveredOnLinkPrefixes {
			expectedRt[i] = tcpip.Route{prefixes[i], tcpip.Address([]byte(nil)), 1}
		}
	}

	e.InjectInbound(header.IPv6ProtocolNumber, raBufWithOpts(llAddr1, 0, optSer))
	for i := 0; i < stack.MaxDiscoveredOnLinkPrefixes+2; i++ {
		if i < stack.MaxDiscoveredOnLinkPrefixes {
			select {
			case r := <-ndpDisp.prefixC:
				if r.nicID != 1 {
					t.Fatalf("got r.nicID = %d, want = 1", r.nicID)
				}
				if r.prefix != prefixes[i] {
					t.Fatalf("got r.prefix = %s, want = %s", r.prefix, prefixes[i])
				}
				if !r.discovered {
					t.Fatal("got r.discovered = false, want = true")
				}
			case <-time.After(defaultTimeout):
				t.Fatal("timeout waiting for prefix discovery event")
			}
		} else {
			select {
			case <-ndpDisp.prefixC:
				t.Fatal("should not have discovered a new prefix after we already discovered the max number of prefixes")
			case <-time.After(defaultTimeout):
			}
		}
	}

	// Should only have device routes for the first
	// stack.MaxDiscoveredOnLinkPrefixes discovered on-link prefixes.
	if got := s.GetRouteTable(); !cmp.Equal(got, expectedRt[:]) {
		t.Fatalf("got GetRouteTable = %v, want = %v", got, expectedRt)
	}
}
