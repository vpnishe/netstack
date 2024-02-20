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

// Package channel provides the implemention of channel-based data-link layer
// endpoints. Such endpoints allow injection of inbound packets and store
// outbound packets in a channel.
package channel

import (
	"errors"

	"github.com/vpnishe/netstack/tcpip"
	"github.com/vpnishe/netstack/tcpip/buffer"
	"github.com/vpnishe/netstack/tcpip/stack"
)

// PacketInfo holds all the information about an outbound packet.
type PacketInfo struct {
	Pkt   tcpip.PacketBuffer
	Proto tcpip.NetworkProtocolNumber
	GSO   *stack.GSO
}

// Endpoint is link layer endpoint that stores outbound packets in a channel
// and allows injection of inbound packets.
type Endpoint struct {
	dispatcher stack.NetworkDispatcher
	mtu        uint32
	linkAddr   tcpip.LinkAddress
	GSO        bool

	// C is where outbound packets are queued.
	ch chan PacketInfo
}

// New creates a new channel endpoint.
func New(size int, mtu uint32, linkAddr tcpip.LinkAddress) *Endpoint {
	return &Endpoint{
		ch:       make(chan PacketInfo, size),
		mtu:      mtu,
		linkAddr: linkAddr,
	}
}

// Drain removes all outbound packets from the channel and counts them.
func (e *Endpoint) Drain() int {

	if e.ch == nil {
		return 0
	}

	c := 0
	for {
		select {
		case <-e.ch:
			c++
		default:
			return c
		}
	}
}

func (e *Endpoint) Read() (*PacketInfo, error) {

	if e.ch == nil {
		return nil, errors.New("link channel is closed")
	}

	pkgInfo, ok := <-e.ch
	if !ok {
		return nil, errors.New("link channel closed")
	}
	return &pkgInfo, nil

}

func (e *Endpoint) Close() {
	if e.ch == nil {
		return
	}
	ch := e.ch
	e.ch = nil
	close(ch)

}

// InjectInbound injects an inbound packet.
func (e *Endpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer) {
	e.InjectLinkAddr(protocol, "", pkt)
}

// InjectLinkAddr injects an inbound packet with a remote link address.
func (e *Endpoint) InjectLinkAddr(protocol tcpip.NetworkProtocolNumber, remote tcpip.LinkAddress, pkt tcpip.PacketBuffer) {
	e.dispatcher.DeliverNetworkPacket(e, remote, "" /* local */, protocol, pkt)
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *Endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *Endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	caps := stack.LinkEndpointCapabilities(0)
	if e.GSO {
		caps |= stack.CapabilityHardwareGSO
	}
	return caps
}

// GSOMaxSize returns the maximum GSO packet size.
func (*Endpoint) GSOMaxSize() uint32 {
	return 1 << 15
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	return e.linkAddr
}

// WritePacket stores outbound packets into the channel.
func (e *Endpoint) WritePacket(_ *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer) *tcpip.Error {

	if e.ch == nil {
		return tcpip.ErrBadLinkEndpoint
	}

	p := PacketInfo{
		Pkt:   pkt,
		Proto: protocol,
		GSO:   gso,
	}

	select {
	case e.ch <- p:
	default:
	}

	return nil
}

// WritePackets stores outbound packets into the channel.
func (e *Endpoint) WritePackets(_ *stack.Route, gso *stack.GSO, hdrs []stack.PacketDescriptor, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {

	if e.ch == nil {
		return 0, tcpip.ErrBadLinkEndpoint
	}

	payloadView := payload.ToView()
	n := 0
packetLoop:
	for _, hdr := range hdrs {
		off := hdr.Off
		size := hdr.Size
		p := PacketInfo{
			Pkt: tcpip.PacketBuffer{
				Header: hdr.Hdr,
				Data:   buffer.NewViewFromBytes(payloadView[off : off+size]).ToVectorisedView(),
			},
			Proto: protocol,
			GSO:   gso,
		}

		select {
		case e.ch <- p:
			n++
		default:
			break packetLoop
		}
	}

	return n, nil
}

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket.
func (e *Endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	if e.ch == nil {
		return tcpip.ErrBadLinkEndpoint
	}
	p := PacketInfo{
		Pkt:   tcpip.PacketBuffer{Data: vv},
		Proto: 0,
		GSO:   nil,
	}

	select {
	case e.ch <- p:
	default:
	}

	return nil
}

// Wait implements stack.LinkEndpoint.Wait.
func (*Endpoint) Wait() {}
