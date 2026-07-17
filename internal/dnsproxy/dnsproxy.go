// Package dnsproxy answers DNS for the policed clients: allowed names are
// forwarded upstream and their A records pinned into the nftables set,
// everything else is refused without leaving the box.
package dnsproxy

import (
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/m8-t/fqdn-egress/internal/allowlist"
)

// Pinner is the nft side: make ip reachable for ttl.
type Pinner interface {
	Pin(ip netip.Addr, ttl time.Duration) error
}

// Stats receives what the proxy observes. Implementations must be safe
// for concurrent use.
type Stats interface {
	Query(verdict string) // allowed, denied, error
	Upstream(rtt time.Duration)
}

type noStats struct{}

func (noStats) Query(string)           {}
func (noStats) Upstream(time.Duration) {}

type Config struct {
	Listen   string
	Upstream string
	Answer   string // nxdomain or refuse
	MinTTL   time.Duration
	MaxTTL   time.Duration
}

type Proxy struct {
	cfg   Config
	pin   Pinner
	list  atomic.Pointer[allowlist.List]
	log   *slog.Logger
	stats Stats

	udp    *dns.Server
	tcp    *dns.Server
	client *dns.Client
}

func New(cfg Config, list *allowlist.List, pin Pinner, log *slog.Logger) *Proxy {
	p := &Proxy{
		cfg:    cfg,
		pin:    pin,
		log:    log,
		stats:  noStats{},
		client: &dns.Client{Timeout: 5 * time.Second},
	}
	p.list.Store(list)
	return p
}

// SetStats must be called before Listen.
func (p *Proxy) SetStats(s Stats) {
	p.stats = s
}

// AllowlistLen reports the size of the active list.
func (p *Proxy) AllowlistLen() int {
	return p.list.Load().Len()
}

// SetAllowlist swaps the list; in-flight queries keep the old one.
func (p *Proxy) SetAllowlist(l *allowlist.List) {
	p.list.Store(l)
}

// Listen binds UDP and TCP on cfg.Listen.
func (p *Proxy) Listen() error {
	pc, err := net.ListenPacket("udp", p.cfg.Listen)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		pc.Close()
		return err
	}
	p.udp = &dns.Server{PacketConn: pc, Handler: p}
	p.tcp = &dns.Server{Listener: ln, Handler: p}
	return nil
}

// Serve answers queries on the bound sockets until Shutdown.
func (p *Proxy) Serve() error {
	errc := make(chan error, 2)
	go func() { errc <- p.udp.ActivateAndServe() }()
	go func() { errc <- p.tcp.ActivateAndServe() }()
	return <-errc
}

// Addr returns the bound UDP address, useful when listening on port 0.
func (p *Proxy) Addr() net.Addr {
	return p.udp.PacketConn.LocalAddr()
}

func (p *Proxy) Shutdown() {
	if p.udp != nil {
		p.udp.Shutdown()
	}
	if p.tcp != nil {
		p.tcp.Shutdown()
	}
}

func (p *Proxy) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) != 1 {
		p.reply(w, refused(req))
		return
	}
	q := req.Question[0]
	name := q.Name

	if q.Qclass != dns.ClassINET || !p.list.Load().Match(name) {
		p.log.Info("query denied", "name", name, "type", dns.TypeToString[q.Qtype])
		p.stats.Query("denied")
		p.reply(w, p.deny(req))
		return
	}

	// v4 only for now: answering AAAA would hand out addresses the
	// ruleset cannot pin, so return an empty answer instead.
	if q.Qtype == dns.TypeAAAA {
		m := new(dns.Msg)
		m.SetReply(req)
		p.stats.Query("allowed")
		p.reply(w, m)
		return
	}

	resp, err := p.forward(req)
	if err != nil {
		p.log.Error("upstream query failed", "name", name, "err", err)
		p.stats.Query("error")
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		p.reply(w, m)
		return
	}
	p.stats.Query("allowed")

	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.A.To4())
		if !ok {
			continue
		}
		ttl := p.clamp(time.Duration(a.Hdr.Ttl) * time.Second)
		if err := p.pin.Pin(ip, ttl); err != nil {
			p.log.Error("pin failed", "ip", ip, "err", err)
			continue
		}
		p.log.Debug("pinned", "name", name, "ip", ip, "ttl", ttl)
	}
	p.reply(w, resp)
}

func (p *Proxy) forward(req *dns.Msg) (*dns.Msg, error) {
	resp, rtt, err := p.client.Exchange(req, p.cfg.Upstream)
	if err == nil && resp.Truncated {
		tcp := *p.client
		tcp.Net = "tcp"
		resp, rtt, err = tcp.Exchange(req, p.cfg.Upstream)
	}
	if err == nil {
		p.stats.Upstream(rtt)
	}
	return resp, err
}

func (p *Proxy) clamp(ttl time.Duration) time.Duration {
	if ttl < p.cfg.MinTTL {
		return p.cfg.MinTTL
	}
	if ttl > p.cfg.MaxTTL {
		return p.cfg.MaxTTL
	}
	return ttl
}

func (p *Proxy) deny(req *dns.Msg) *dns.Msg {
	if p.cfg.Answer == "refuse" {
		return refused(req)
	}
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)
	return m
}

func refused(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeRefused)
	return m
}

func (p *Proxy) reply(w dns.ResponseWriter, m *dns.Msg) {
	if err := w.WriteMsg(m); err != nil {
		p.log.Error("write reply", "err", err)
	}
}
