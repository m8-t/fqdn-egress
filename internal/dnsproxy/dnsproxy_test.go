package dnsproxy

import (
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/m8-t/fqdn-egress/internal/allowlist"
)

type fakePinner struct {
	mu   sync.Mutex
	pins map[netip.Addr]time.Duration
}

func (f *fakePinner) Pin(ip netip.Addr, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pins == nil {
		f.pins = make(map[netip.Addr]time.Duration)
	}
	f.pins[ip] = ttl
	return nil
}

func (f *fakePinner) get(ip string) (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ttl, ok := f.pins[netip.MustParseAddr(ip)]
	return ttl, ok
}

// upstream serves canned answers for the tests.
func upstream(t *testing.T, records map[string][]dns.RR) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = records[req.Question[0].Name]
			w.WriteMsg(m)
		}),
	}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newProxy(t *testing.T, cfg Config, allow string, pin Pinner, stats ...Stats) *Proxy {
	t.Helper()
	list, err := allowlist.Parse(strings.NewReader(allow))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	if cfg.Answer == "" {
		cfg.Answer = "nxdomain"
	}
	if cfg.MinTTL == 0 {
		cfg.MinTTL = 30 * time.Second
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = time.Hour
	}
	p := New(cfg, list, pin, slog.New(slog.DiscardHandler))
	if len(stats) > 0 {
		p.SetStats(stats[0])
	}
	if err := p.Listen(); err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Shutdown)
	return p
}

func query(t *testing.T, addr net.Addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Timeout: 2 * time.Second}
	resp, _, err := c.Exchange(req, addr.String())
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAllowedQueryPinsAnswer(t *testing.T) {
	up := upstream(t, map[string][]dns.RR{
		"example.com.": {rr(t, "example.com. 300 IN A 93.184.216.34")},
	})
	pin := &fakePinner{}
	p := newProxy(t, Config{Upstream: up}, "example.com", pin)

	resp := query(t, p.Addr(), "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers", len(resp.Answer))
	}
	ttl, ok := pin.get("93.184.216.34")
	if !ok {
		t.Fatal("IP not pinned")
	}
	if ttl != 300*time.Second {
		t.Errorf("ttl = %s, want 5m", ttl)
	}
}

func TestTTLClamping(t *testing.T) {
	up := upstream(t, map[string][]dns.RR{
		"short.test.": {rr(t, "short.test. 1 IN A 192.0.2.1")},
		"long.test.":  {rr(t, "long.test. 86400 IN A 192.0.2.2")},
	})
	pin := &fakePinner{}
	cfg := Config{Upstream: up, MinTTL: 30 * time.Second, MaxTTL: time.Hour}
	p := newProxy(t, cfg, "*.test", pin)

	query(t, p.Addr(), "short.test", dns.TypeA)
	query(t, p.Addr(), "long.test", dns.TypeA)

	if ttl, _ := pin.get("192.0.2.1"); ttl != 30*time.Second {
		t.Errorf("short ttl = %s, want 30s", ttl)
	}
	if ttl, _ := pin.get("192.0.2.2"); ttl != time.Hour {
		t.Errorf("long ttl = %s, want 1h", ttl)
	}
}

func TestDeniedName(t *testing.T) {
	up := upstream(t, nil)
	pin := &fakePinner{}
	p := newProxy(t, Config{Upstream: up}, "example.com", pin)

	resp := query(t, p.Addr(), "evil.test", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
	if len(pin.pins) != 0 {
		t.Error("denied query pinned an IP")
	}
}

func TestDeniedNameRefuseMode(t *testing.T) {
	up := upstream(t, nil)
	p := newProxy(t, Config{Upstream: up, Answer: "refuse"}, "example.com", &fakePinner{})

	resp := query(t, p.Addr(), "evil.test", dns.TypeA)
	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
	}
}

func TestAAAAFiltered(t *testing.T) {
	up := upstream(t, map[string][]dns.RR{
		"example.com.": {rr(t, "example.com. 300 IN AAAA 2001:db8::1")},
	})
	pin := &fakePinner{}
	p := newProxy(t, Config{Upstream: up}, "example.com", pin)

	resp := query(t, p.Addr(), "example.com", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 0 {
		t.Errorf("got %d answers, want none", len(resp.Answer))
	}
	if len(pin.pins) != 0 {
		t.Error("AAAA query pinned an IP")
	}
}

func TestCNAMEChainPinsARecords(t *testing.T) {
	up := upstream(t, map[string][]dns.RR{
		"www.example.com.": {
			rr(t, "www.example.com. 300 IN CNAME cdn.example.net."),
			rr(t, "cdn.example.net. 60 IN A 198.51.100.7"),
		},
	})
	pin := &fakePinner{}
	p := newProxy(t, Config{Upstream: up}, "www.example.com", pin)

	query(t, p.Addr(), "www.example.com", dns.TypeA)
	if _, ok := pin.get("198.51.100.7"); !ok {
		t.Error("A record behind CNAME not pinned")
	}
}

func TestUpstreamFailure(t *testing.T) {
	// closed port: queries time out
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := pc.LocalAddr().String()
	pc.Close()

	p := newProxy(t, Config{Upstream: dead}, "example.com", &fakePinner{})
	resp := query(t, p.Addr(), "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
}

type fakeStats struct {
	mu       sync.Mutex
	verdicts map[string]int
	rtts     int
}

func (f *fakeStats) Query(verdict string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.verdicts == nil {
		f.verdicts = make(map[string]int)
	}
	f.verdicts[verdict]++
}

func (f *fakeStats) Upstream(time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rtts++
}

func TestStatsRecorded(t *testing.T) {
	up := upstream(t, map[string][]dns.RR{
		"example.com.": {rr(t, "example.com. 300 IN A 93.184.216.34")},
	})
	stats := &fakeStats{}
	p := newProxy(t, Config{Upstream: up}, "example.com", &fakePinner{}, stats)

	query(t, p.Addr(), "example.com", dns.TypeA)
	query(t, p.Addr(), "evil.test", dns.TypeA)

	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.verdicts["allowed"] != 1 || stats.verdicts["denied"] != 1 {
		t.Errorf("verdicts = %v", stats.verdicts)
	}
	if stats.rtts != 1 {
		t.Errorf("recorded %d upstream rtts, want 1", stats.rtts)
	}
}

func TestAllowlistReload(t *testing.T) {
	up := upstream(t, map[string][]dns.RR{
		"new.test.": {rr(t, "new.test. 300 IN A 192.0.2.9")},
	})
	pin := &fakePinner{}
	p := newProxy(t, Config{Upstream: up}, "example.com", pin)

	if resp := query(t, p.Addr(), "new.test", dns.TypeA); resp.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN before reload", dns.RcodeToString[resp.Rcode])
	}

	list, err := allowlist.Parse(strings.NewReader("new.test"))
	if err != nil {
		t.Fatal(err)
	}
	p.SetAllowlist(list)

	if resp := query(t, p.Addr(), "new.test", dns.TypeA); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR after reload", dns.RcodeToString[resp.Rcode])
	}
}
