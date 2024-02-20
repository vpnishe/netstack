package example

import (
	"errors"
	"io"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/polevpn/elog"
	"github.com/vpnishe/netstack/tcpip"
	"github.com/vpnishe/netstack/tcpip/buffer"
	"github.com/vpnishe/netstack/tcpip/link/channel"
	"github.com/vpnishe/netstack/tcpip/network/arp"
	"github.com/vpnishe/netstack/tcpip/network/ipv4"
	"github.com/vpnishe/netstack/tcpip/stack"
	"github.com/vpnishe/netstack/tcpip/transport/tcp"
	"github.com/vpnishe/netstack/tcpip/transport/udp"
	"github.com/vpnishe/netstack/waiter"
)

const (
	TCP_MAX_CONNECTION_SIZE  = 1024
	FORWARD_CH_WRITE_SIZE    = 4096
	UDP_MAX_BUFFER_SIZE      = 8192
	TCP_MAX_BUFFER_SIZE      = 8192
	UDP_READ_BUFFER_SIZE     = 524288
	UDP_WRITE_BUFFER_SIZE    = 262144
	TCP_READ_BUFFER_SIZE     = 524288
	TCP_WRITE_BUFFER_SIZE    = 262144
	UDP_CONNECTION_IDLE_TIME = 1
	CH_WRITE_SIZE            = 100
	TCP_CONNECT_TIMEOUT      = 5
	TCP_CONNECT_RETRY        = 3
)

type LocalForwarder struct {
	s       *stack.Stack
	ep      *channel.Endpoint
	wq      *waiter.Queue
	closed  bool
	handler func([]byte)
	localip string
}

func PanicHandler() {
	if err := recover(); err != nil {
		elog.Error("Panic Exception:", err)
		elog.Error(string(debug.Stack()))
	}
}

func NewLocalForwarder() (*LocalForwarder, error) {

	forwarder := &LocalForwarder{}

	//create MAC address
	maddr, err := net.ParseMAC("01:01:01:01:01:01")
	if err != nil {
		return nil, err
	}

	// Create the net stack with ip and tcp protocols, then add a tun-based
	// NIC and address.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), arp.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{tcp.NewProtocol(), udp.NewProtocol()},
	})

	//create link channel for packet input
	ep := channel.New(FORWARD_CH_WRITE_SIZE, 1500, tcpip.LinkAddress(maddr))

	//create NIC
	if err := s.CreateNIC(1, ep); err != nil {
		return nil, errors.New(err.String())
	}

	//create a subnet for 0.0.0.0/0
	subnet1, err := tcpip.NewSubnet(tcpip.Address(net.IPv4(0, 0, 0, 0).To4()), tcpip.AddressMask(net.IPv4Mask(0, 0, 0, 0)))
	if err != nil {
		return nil, err
	}

	//add 0.0.0.0/0 to netstack,then netstack can process destination address in "0.0.0.0/0"
	if err := s.AddAddressRange(1, ipv4.ProtocolNumber, subnet1); err != nil {
		return nil, errors.New(err.String())
	}

	//add arp address
	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		return nil, errors.New(err.String())
	}

	subnet, err := tcpip.NewSubnet(tcpip.Address(net.IPv4(0, 0, 0, 0).To4()), tcpip.AddressMask(net.IPv4Mask(0, 0, 0, 0)))
	if err != nil {
		return nil, err
	}
	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         1,
		},
	})

	//create udp forwarder
	uf := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		go forwarder.forwardUDP(r)
	})

	//set udp packet handler
	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)

	//create tcp forworder
	tf := tcp.NewForwarder(s, 0, TCP_MAX_CONNECTION_SIZE, func(r *tcp.ForwarderRequest) {
		go forwarder.forwardTCP(r)
	})
	//set tcp packet handler
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	forwarder.closed = false
	forwarder.s = s
	forwarder.ep = ep
	forwarder.wq = &waiter.Queue{}
	return forwarder, nil

}

func (lf *LocalForwarder) SetPacketHandler(handler func([]byte)) {
	lf.handler = handler
}

func (lf *LocalForwarder) SetLocalIP(ip string) {
	lf.localip = ip
}

//packet from tun device tcp/ip
func (lf *LocalForwarder) Write(pkg []byte) {
	if lf.closed {
		return
	}
	pkgBuffer := tcpip.PacketBuffer{Data: buffer.NewViewFromBytes(pkg).ToVectorisedView()}
	lf.ep.InjectInbound(ipv4.ProtocolNumber, pkgBuffer)
}

//packet from netstack
func (lf *LocalForwarder) read() {
	for {
		pkgInfo, err := lf.ep.Read()
		if err != nil {
			elog.Info(err)
			return
		}
		view := buffer.NewVectorisedView(1, []buffer.View{pkgInfo.Pkt.Header.View()})
		view.Append(pkgInfo.Pkt.Data)
		if lf.handler != nil {
			lf.handler(view.ToView())
		}
	}
}

func (lf *LocalForwarder) StartProcess() {
	go lf.read()
}

func (lf *LocalForwarder) ClearConnect() {
	lf.wq.Notify(waiter.EventIn)
}

func (lf *LocalForwarder) Close() {
	defer PanicHandler()

	if lf.closed {
		return
	}
	lf.closed = true

	lf.wq.Notify(waiter.EventIn)
	time.Sleep(time.Millisecond * 100)
	lf.ep.Close()
}

func (lf *LocalForwarder) forwardTCP(r *tcp.ForwarderRequest) {

	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		elog.Error("create tcp endpint error", err)
		r.Complete(true)
		return
	}

	if lf.closed {
		r.Complete(true)
		ep.Close()
		return
	}

	elog.Debug(r.ID(), "tcp connect")

	var err1 error

	localip := lf.localip
	var laddr *net.TCPAddr
	if localip != "" {
		laddr, _ = net.ResolveTCPAddr("tcp4", localip+":0")
	}

	addr, _ := ep.GetLocalAddress()
	raddr := addr.Addr.String() + ":" + strconv.Itoa(int(addr.Port))
	var conn net.Conn
	for i := 0; i < TCP_CONNECT_RETRY; i++ {
		d := net.Dialer{Timeout: time.Second * TCP_CONNECT_TIMEOUT, LocalAddr: laddr}
		conn, err1 = d.Dial("tcp4", raddr)
		if err1 != nil {
			continue
		}
		break
	}

	if err1 != nil {
		elog.Println("conn dial fail,", err1)
		r.Complete(true)
		ep.Close()
		return
	}

	tcpconn := conn.(*net.TCPConn)
	tcpconn.SetNoDelay(true)
	tcpconn.SetKeepAlive(true)
	tcpconn.SetWriteBuffer(TCP_WRITE_BUFFER_SIZE)
	tcpconn.SetReadBuffer(TCP_READ_BUFFER_SIZE)
	tcpconn.SetKeepAlivePeriod(time.Second * 15)

	go lf.tcpRead(r, wq, ep, conn)
	go lf.tcpWrite(r, wq, ep, conn)
}

func (lf *LocalForwarder) udpRead(r *udp.ForwarderRequest, ep tcpip.Endpoint, wq *waiter.Queue, conn *net.UDPConn, timer *time.Ticker) {

	defer func() {
		elog.Debug(r.ID(), "udp closed")
		ep.Close()
		conn.Close()
	}()

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventIn)
	defer wq.EventUnregister(&waitEntry)

	gwaitEntry, gnotifyCh := waiter.NewChannelEntry(nil)

	lf.wq.EventRegister(&gwaitEntry, waiter.EventIn)
	defer lf.wq.EventUnregister(&gwaitEntry)

	wch := make(chan []byte, CH_WRITE_SIZE)

	defer close(wch)

	writer := func() {
		for {
			pkt, ok := <-wch
			if !ok {
				elog.Debug("udp wch closed,exit write process")
				return
			} else {
				_, err1 := conn.Write(pkt)
				if err1 != nil {
					if err1 != io.EOF && !strings.Contains(err1.Error(), "use of closed network connection") {
						elog.Info("udp conn write error", err1)
					}
					return
				}
			}
		}
	}

	go writer()

	lastTime := time.Now()

	for {
		var addr tcpip.FullAddress
		v, _, err := ep.Read(&addr)
		if err != nil {
			if err == tcpip.ErrWouldBlock {

				select {
				case <-notifyCh:
					continue
				case <-gnotifyCh:
					return
				case <-timer.C:
					if time.Now().Sub(lastTime) > time.Minute*UDP_CONNECTION_IDLE_TIME {
						elog.Infof("udp %v connection expired,close it", r.ID())
						timer.Stop()
						return
					} else {
						continue
					}
				}
			} else if err != tcpip.ErrClosedForReceive && err != tcpip.ErrClosedForSend {
				elog.Info("udp ep read fail,", err)
			}
			return
		}

		wch <- v
		lastTime = time.Now()
	}
}

func (lf *LocalForwarder) udpWrite(r *udp.ForwarderRequest, ep tcpip.Endpoint, wq *waiter.Queue, conn *net.UDPConn, addr *tcpip.FullAddress) {

	defer func() {
		ep.Close()
		conn.Close()
	}()

	for {
		var udppkg []byte = make([]byte, UDP_MAX_BUFFER_SIZE)
		n, err1 := conn.Read(udppkg)

		if err1 != nil {
			if err1 != io.EOF &&
				!strings.Contains(err1.Error(), "use of closed network connection") &&
				!strings.Contains(err1.Error(), "connection refused") {
				elog.Info("udp conn read error,", err1)
			}
			return
		}
		udppkg1 := udppkg[:n]
		_, _, err := ep.Write(tcpip.SlicePayload(udppkg1), tcpip.WriteOptions{To: addr})
		if err != nil {
			elog.Info("udp ep write fail,", err)
			return
		}
	}
}

func (lf *LocalForwarder) forwardUDP(r *udp.ForwarderRequest) {
	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		elog.Error("create udp endpint error", err)
		return
	}

	if lf.closed {
		ep.Close()
		return
	}

	elog.Debug(r.ID(), "udp connect")

	localip := lf.localip
	var err1 error
	var laddr *net.UDPAddr
	if localip != "" {
		laddr, _ = net.ResolveUDPAddr("udp4", localip+":0")
	}

	raddr, _ := net.ResolveUDPAddr("udp4", r.ID().LocalAddress.To4().String()+":"+strconv.Itoa(int(r.ID().LocalPort)))

	conn, err1 := net.DialUDP("udp4", laddr, raddr)
	if err1 != nil {
		elog.Error("udp conn dial error ", err1)
		ep.Close()
		return
	}

	conn.SetReadBuffer(UDP_READ_BUFFER_SIZE)
	conn.SetWriteBuffer(UDP_WRITE_BUFFER_SIZE)

	timer := time.NewTicker(time.Minute)
	addr := &tcpip.FullAddress{Addr: r.ID().RemoteAddress, Port: r.ID().RemotePort}

	go lf.udpRead(r, ep, wq, conn, timer)
	go lf.udpWrite(r, ep, wq, conn, addr)
}

func (lf *LocalForwarder) tcpRead(r *tcp.ForwarderRequest, wq *waiter.Queue, ep tcpip.Endpoint, conn net.Conn) {
	defer func() {
		elog.Debug(r.ID(), "tcp closed")
		r.Complete(true)
		ep.Close()
		conn.Close()
	}()

	// Create wait queue entry that notifies a channel.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)

	wq.EventRegister(&waitEntry, waiter.EventIn)
	defer wq.EventUnregister(&waitEntry)

	// Create wait queue entry that notifies a channel.
	gwaitEntry, gnotifyCh := waiter.NewChannelEntry(nil)

	lf.wq.EventRegister(&gwaitEntry, waiter.EventIn)
	defer lf.wq.EventUnregister(&gwaitEntry)

	wch := make(chan []byte, CH_WRITE_SIZE)

	defer close(wch)

	writer := func() {
		for {
			pkt, ok := <-wch
			if !ok {
				elog.Debug("wch closed,exit write process")
				return
			} else {
				_, err1 := conn.Write(pkt)
				if err1 != nil {
					if err1 != io.EOF && !strings.Contains(err1.Error(), "use of closed network connection") {
						elog.Infof("tcp %v conn write error,%v", r.ID(), err1)
					}
					return
				}
			}
		}
	}

	go writer()

	for {
		v, _, err := ep.Read(nil)
		if err != nil {

			if err == tcpip.ErrWouldBlock {
				select {
				case <-notifyCh:
					continue
				case <-gnotifyCh:
					return
				}

			} else if err != tcpip.ErrClosedForReceive && err != tcpip.ErrClosedForSend {
				elog.Infof("tcp %v endpoint read fail,%v", r.ID(), err)
			}
			return
		}
		wch <- v
	}
}

func (lf *LocalForwarder) tcpWrite(r *tcp.ForwarderRequest, wq *waiter.Queue, ep tcpip.Endpoint, conn net.Conn) {
	defer func() {
		ep.Close()
		conn.Close()
	}()

	for {
		var buf []byte = make([]byte, TCP_MAX_BUFFER_SIZE)
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				elog.Infof("tcp %v conn read error,%v", r.ID(), err)
			}
			break
		}

		ep.Write(tcpip.SlicePayload(buf[:n]), tcpip.WriteOptions{})
	}
}
