// https://9p.io/sources/plan9/sys/src/cmd/ip/ping.c
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	MAXMSG  = 32
	SLEEPMS = 1000

	SECOND int64 = 1000000000
	MINUTE       = 60 * SECOND

	ICMP_HDRSIZE = 8
)

type Req struct {
	seq     uint16 /* sequence number */
	time    int64  /* time sent */
	rtt     int64
	ttl     int
	replied bool
	next    *Req
}

type Proto struct {
	version   int
	net       string
	echocmd   icmp.Type
	echoreply icmp.Type
	iphdrsz   int
	number    int /* https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml */

	prreply func(r *Req, h *header)
	prlost  func(seq uint16, h *header)
}

type header struct {
	src net.Addr
	dst net.Addr
	ttl int
}

var first *Req /* request list */
var last *Req  /* ... */
var listlock sync.Mutex

var addresses bool
var debug bool
var flood bool
var lostmsgs int64
var lostonly bool
var quiet bool
var rcvdmsgs int64
var rint bool
var firstseq uint16
var sum int64
var waittime int64 = 5000

var wg sync.WaitGroup

var network string
var target net.IP
var me net.IP

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s [-6alq] [-s msgsize] [-i millisecs] [-n #pings] dest\n",
		os.Args[0])

	os.Exit(1)
}

func prlost4(seq uint16, h *header) {
	fmt.Printf("lost %d: %v -> %v\n", seq, h.src, h.dst)
}

func prlost6(seq uint16, h *header) {
	fmt.Printf("lost %d: %v -> %v\n", seq, h.src, h.dst)
}

func prreply4(r *Req, h *header) {
	fmt.Printf("%d: %v -> %v rtt %d µs, avg rtt %d µs, ttl = %d\n",
		r.seq-firstseq, h.src, h.dst, r.rtt, sum/rcvdmsgs,
		r.ttl)
}

func prreply6(r *Req, h *header) {
	fmt.Printf("%d: %v -> %v rtt %d µs, avg rtt %d µs, ttl = %d\n",
		r.seq-firstseq, h.src, h.dst, r.rtt, sum/rcvdmsgs,
		r.ttl)
}

var v4pr = Proto{
	version:   4,
	net:       "ip4:icmp",
	echocmd:   ipv4.ICMPTypeEcho,
	echoreply: ipv4.ICMPTypeEchoReply,
	iphdrsz:   0,
	number:    1,

	prreply: prreply4,
	prlost:  prlost4,
}

var v6pr = Proto{
	version:   6,
	net:       "ip6:ipv6-icmp",
	echocmd:   ipv6.ICMPTypeEchoRequest,
	echoreply: ipv6.ICMPTypeEchoReply,
	iphdrsz:   0,
	number:    58,

	prreply: prreply6,
	prlost:  prlost6,
}

var proto = &v4pr

func clean(seq uint16, now int64, h *header) {
	// fmt.Printf("CLEAN\n")
	var ttl int
	var l **Req
	var r *Req

	ttl = 0

	if h != nil {
		ttl = h.ttl
	}

	listlock.Lock()
	last = nil
	for l = &first; *l != nil; {
		r = *l

		if h != nil && r.seq == seq {
			r.rtt = now - r.time
			r.ttl = ttl
			reply(r, h)
		}

		if now-r.time > MINUTE {
			*l = r.next
			r.rtt = now - r.time
			if h != nil {
				r.ttl = ttl
			}
			if !r.replied {
				lost(r, h)
			}
		} else {
			last = r
			l = &r.next
		}
	}
	listlock.Unlock()
}

func sender(conn *icmp.PacketConn, msglen int, interval int64, n int64) {
	wg.Add(1)

	rand.Seed(time.Now().Unix())
	seq := uint16(rand.Intn(255))
	firstseq = seq

	icmpMsg := icmp.Message{}
	icmpMsg.Body = &icmp.Echo{
		ID:   os.Getpid() & 0xffff,
		Data: make([]byte, msglen-(proto.iphdrsz+ICMP_HDRSIZE)),
	}
	buf := &(icmpMsg.Body.(*icmp.Echo).Data)
	for i := proto.iphdrsz + ICMP_HDRSIZE; i < msglen; i++ {
		(*buf)[i-(proto.iphdrsz+ICMP_HDRSIZE)] = byte(i)
	}
	icmpMsg.Type = proto.echocmd
	icmpMsg.Code = 0

	if addresses {
		fmt.Printf("\t%v -> %v\n", me, target)
	}

	if rint && interval <= 0 {
		rint = false
	}
	extra := 0
	for i := int64(0); i < n; i++ {
		if i != 0 {
			if rint {
				extra = rand.Intn(int(interval))
			}

			time.Sleep(time.Duration(int(interval)+extra) * time.Millisecond)
		}
		r := &Req{}
		icmpMsg.Body.(*icmp.Echo).Seq = int(seq)
		r.seq = seq
		r.next = nil
		r.replied = false
		r.time = time.Now().UnixNano() /* avoid early free in reply! */
		listlock.Lock()
		if first == nil {
			first = r
		} else {
			last.next = r
		}
		last = r
		listlock.Unlock()
		r.time = time.Now().UnixNano()
		buf, err := icmpMsg.Marshal(nil)
		if err != nil {
			fmt.Printf("%s: write failed: %s\n", os.Args[0], err)
			return
		}

		if write(conn, buf, target) < msglen-(proto.iphdrsz+ICMP_HDRSIZE) {
			fmt.Printf("%s: write failed: received bytes: %d, want: %d\n", os.Args[0], n, msglen)
			return
		}

		seq++
	}
	wg.Done()
}

func rcvr(conn *icmp.PacketConn, msglen int, interval int64, nmsg int64) {
	wg.Add(1)

	var munged int
	var buf = make([]byte, 64*1024+512)
	var r *Req

	sum = 0
	for lostmsgs+rcvdmsgs < nmsg {
		alarm := time.Now().Add(time.Duration(((nmsg-lostmsgs-rcvdmsgs)*interval + waittime)) * time.Millisecond)
		n, h := read(conn, &buf, alarm)

		now := time.Now().UnixNano()
		if n <= 0 { /* read interrupted - time to go */
			clean(0, now+MINUTE, nil)
			continue
		}

		if n < msglen-(proto.iphdrsz+ICMP_HDRSIZE) {
			fmt.Printf("bad len %d/%d\n", n, msglen)
			continue
		}

		icmpMsg, err := icmp.ParseMessage(proto.number, buf[:n])
		if err != nil {
			fmt.Printf("error parsing message %v\n", err)
		}

		munged = 0
		for i := proto.iphdrsz + ICMP_HDRSIZE; i < msglen; i++ {
			if buf[i] != byte(i) {
				munged++
			}
		}
		if munged > 0 {
			fmt.Printf("corrupted reply\n")
		}

		// TODO: icmpMsg.Type is parsed incorrectly in some cases
		xseq := binary.BigEndian.Uint16(buf[6:8])
		if /*icmpMsg.Type != proto.echoreply ||*/ icmpMsg.Code != 0 {
			fmt.Printf("bad type/code/sequence %d/%d/%d (want %d/%d/%d)\n",
				icmpMsg.Type, icmpMsg.Code, xseq,
				proto.echoreply, 0, xseq)
			continue
		}

		clean(xseq, now, h)
	}

	listlock.Lock()
	for r = first; r != nil; r = r.next {
		if !r.replied {
			lostmsgs++
		}
	}
	listlock.Unlock()

	if !quiet && lostmsgs > 0 {
		fmt.Printf("%d out of %d messages lost\n", lostmsgs,
			lostmsgs+rcvdmsgs)
	}
	wg.Done()
	os.Exit(0)
}

/* side effect: sets network & target */
func isv4name(name string) bool {
	ip := net.ParseIP(name)
	if ip != nil {
		target = ip
		if ip != nil && ip.To4() != nil {
			return true
		}
		if ip != nil && ip.To16() != nil {
			return false
		}
	}

	addrs, err := net.LookupIP(name)
	if err != nil || len(addrs) == 0 {
		return false
	}

	var resIPV4 *net.IP
	var resIPV6 *net.IP
	for _, addr := range addrs {
		addr := addr
		if resIPV4 == nil && addr.To4() != nil {
			resIPV4 = &addr
		}
		if resIPV6 == nil && addr.To16() != nil {
			resIPV6 = &addr
		}
	}

	if resIPV4 != nil {
		return isv4name(resIPV4.String())
	}

	return isv4name(resIPV6.String())
}

// http://man.cat-v.org/plan_9/8/ping
func main() {
	var msglen = 0
	var interval int64 = 0
	var nmsg int64 = MAXMSG

	var flagIPV6 bool
	var flagAddress bool
	var flagDebug bool
	var flagFlood bool
	var flagInterval string
	var flagLostOnly bool
	var flagNMsg string
	var flagQuiet bool
	var flagRInt bool
	var flagMsgLen string
	var flagWaitTime string

	flag.BoolVar(&flagIPV6, "6", false, "")
	flag.BoolVar(&flagAddress, "a", false, "")
	flag.BoolVar(&flagDebug, "d", false, "")
	flag.BoolVar(&flagFlood, "f", false, "")
	flag.StringVar(&flagInterval, "i", "", "")
	flag.BoolVar(&flagLostOnly, "l", false, "")
	flag.StringVar(&flagNMsg, "n", "", "")
	flag.BoolVar(&flagQuiet, "q", false, "")
	flag.BoolVar(&flagRInt, "r", false, "")
	flag.StringVar(&flagMsgLen, "s", "", "")
	flag.StringVar(&flagWaitTime, "w", "", "")

	flag.Usage = usage
	flag.Parse()

	if flagIPV6 {
		proto = &v6pr
	}

	if flagAddress {
		addresses = true
	}

	if flagDebug {
		debug = true
	}

	if flagFlood {
		flood = true
	}

	if flagInterval != "" {
		i, err := strconv.Atoi(flagInterval)
		if err != nil || interval < 0 {
			flag.Usage()
		}
		interval = int64(i)
	}

	if flagLostOnly {
		lostonly = true
	}

	if flagNMsg != "" {
		n, err := strconv.Atoi(flagNMsg)
		if err != nil || n < 0 {
			flag.Usage()
		}
		nmsg = int64(n)
	}

	if flagQuiet {
		quiet = true
	}

	if flagRInt {
		rint = true
	}

	if flagMsgLen != "" {
		m, err := strconv.Atoi(flagMsgLen)
		if err != nil {
			flag.Usage()
		}
		msglen = m
	}

	if flagWaitTime != "" {
		w, err := strconv.Atoi(flagWaitTime)
		if err != nil || waittime < 0 {
			flag.Usage()
		}
		waittime = int64(w)
	}

	if msglen < proto.iphdrsz+ICMP_HDRSIZE {
		msglen = proto.iphdrsz + ICMP_HDRSIZE
	}

	if msglen < 64 {
		msglen = 64
	}

	if msglen >= 64*1024 {
		msglen = 64*1024 - 1
	}

	if interval <= 0 && !flood {
		interval = SLEEPMS
	}

	if len(os.Args) <= 1 {
		flag.Usage()
	}

	catch := make(chan os.Signal, 1)
	signal.Notify(catch)

	if !isv4name(flag.Args()[0]) {
		proto = &v6pr
	}

	if target.IsLoopback() && proto.version == 6 {
		target = net.IPv6loopback
	}

	me = net.IPv4zero
	if proto.version == 6 {
		me = net.IPv6zero
	}

	if target == nil {
		fmt.Printf("%s: couldn't dial %s: %s\n", os.Args[0], flag.Args()[0], proto.net)
		os.Exit(1)
	}

	conn, err := icmp.ListenPacket(proto.net, me.String())
	if conn == nil || err != nil {
		fmt.Printf("%s: couldn't dial %s: %s: %v\n", os.Args[0], flag.Args()[0], proto.net, err)
		os.Exit(1)
	}
	setControlFlags(conn)
	defer conn.Close()

	if !quiet {
		fmt.Printf("sending %d %d byte messages %d ms apart to %+v\n",
			nmsg, msglen, interval, target)
	}

	go rcvr(conn, msglen, interval, nmsg)
	go sender(conn, msglen, interval, nmsg)

	wg.Wait()
	<-catch
}

func reply(r *Req, h *header) {
	sum = sum + r.rtt
	if !r.replied {
		rcvdmsgs++
	}

	if !quiet && !lostonly {
		if addresses {
			proto.prreply(r, h)
		} else {
			fmt.Printf("%d: rtt %d µs, avg rtt %d µs, ttl = %d\n",
				r.seq-firstseq, r.rtt, sum/rcvdmsgs, r.ttl)

		}
	}
	r.replied = true
}

func lost(r *Req, h *header) {
	if !quiet {
		if addresses && h != nil {
			proto.prlost(r.seq-firstseq, h)
		} else {
			fmt.Printf("lost %d\n", r.seq-firstseq)
		}
	}
	lostmsgs++
}

func icmpFilterV4(conn *icmp.PacketConn) {
	var f ipv4.ICMPFilter
	f.SetAll(true)
	f.Accept(ipv4.ICMPTypeDestinationUnreachable)
	f.Accept(ipv4.ICMPTypeTimeExceeded)
	f.Accept(ipv4.ICMPTypeParameterProblem)
	f.Accept(ipv4.ICMPTypeEchoReply)
	f.Accept(ipv4.ICMPTypeExtendedEchoReply)
	if err := conn.IPv4PacketConn().SetICMPFilter(&f); err != nil {
		fmt.Printf("Error setting ICMP filter: %v\n", err)
		os.Exit(1)
	}
}

func icmpFilterV6(conn *icmp.PacketConn) {
	var f ipv6.ICMPFilter
	f.SetAll(true)
	f.Accept(ipv6.ICMPTypeDestinationUnreachable)
	f.Accept(ipv6.ICMPTypePacketTooBig)
	f.Accept(ipv6.ICMPTypeTimeExceeded)
	f.Accept(ipv6.ICMPTypeParameterProblem)
	f.Accept(ipv6.ICMPTypeEchoReply)
	f.Accept(ipv6.ICMPTypeExtendedEchoReply)
	if err := conn.IPv6PacketConn().SetICMPFilter(&f); err != nil {
		fmt.Printf("Error setting ICMP filter: %v\n", err)
		os.Exit(1)
	}
}

func read(conn *icmp.PacketConn, buf *[]byte, alarm time.Time) (n int, h *header) {
	var ttl int
	var src net.Addr
	var dst net.Addr
	if proto.version == 4 {
		err := conn.IPv4PacketConn().SetDeadline(alarm)
		if err != nil {
			fmt.Printf("Error setting read deadline: %v\n", err)
		}

		nR, cm, srcR, err := conn.IPv4PacketConn().ReadFrom(*buf)
		if err != nil {
			fmt.Printf("Error reading from host: %v\n", err)
		}

		n = nR
		src = srcR
		if cm != nil {
			dst = &net.IPAddr{IP: cm.Dst}
			ttl = cm.TTL
		}
	} else {
		err := conn.IPv6PacketConn().SetDeadline(alarm)
		if err != nil {
			fmt.Printf("Error setting read deadline: %v\n", err)
		}
		nR, cm, srcR, err := conn.IPv6PacketConn().ReadFrom(*buf)
		if err != nil {
			fmt.Printf("Error reading from host: %v\n", err)
		}

		n = nR
		src = srcR
		if cm != nil {
			dst = &net.IPAddr{IP: cm.Dst}
			ttl = cm.HopLimit
		}
	}

	h = &header{
		src: src,
		ttl: ttl,
		dst: dst,
	}

	return n, h
}

func write(conn *icmp.PacketConn, buf []byte, target net.IP) (n int) {
	if proto.version == 4 {
		nw, err := conn.IPv4PacketConn().WriteTo(buf, nil, &net.IPAddr{IP: target})
		if err != nil {
			fmt.Printf("%s: write failed: %s\n", os.Args[0], err)
			return
		}
		n = nw
	} else {
		nw, err := conn.IPv6PacketConn().WriteTo(buf, nil, &net.IPAddr{IP: target})
		if err != nil {
			fmt.Printf("%s: write failed: %s\n", os.Args[0], err)
			return
		}
		n = nw
	}
	return n
}

func setControlFlags(conn *icmp.PacketConn) {
	if proto.version == 4 {
		var cm ipv4.ControlFlags
		cm = ipv4.FlagTTL | ipv4.FlagSrc | ipv4.FlagDst
		conn.IPv4PacketConn().SetControlMessage(cm, true)

		icmpFilterV4(conn)
	} else {
		var cm ipv6.ControlFlags
		cm = ipv6.FlagHopLimit | ipv6.FlagSrc | ipv6.FlagDst
		conn.IPv6PacketConn().SetControlMessage(cm, true)

		icmpFilterV6(conn)
	}
}
