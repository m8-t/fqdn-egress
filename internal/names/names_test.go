package names

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestRecordLookup(t *testing.T) {
	tab := New()
	ip := netip.MustParseAddr("140.82.121.4")

	if got := tab.Lookup(ip); got != nil {
		t.Fatalf("empty table returned %v", got)
	}

	tab.Record("github.com", ip)
	time.Sleep(time.Millisecond)
	tab.Record("api.github.com", ip)

	got := tab.Lookup(ip)
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 names", got)
	}
	if got[0] != "api.github.com" {
		t.Errorf("most recent first: got %v", got)
	}
}

func TestEviction(t *testing.T) {
	tab := New()
	for i := 0; i < maxIPs+10; i++ {
		tab.Record("x.test", netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
	if len(tab.ips) > maxIPs {
		t.Errorf("table grew to %d, cap is %d", len(tab.ips), maxIPs)
	}
}

func BenchmarkRecord(b *testing.B) {
	tab := New()
	for i := 0; i < b.N; i++ {
		tab.Record(fmt.Sprintf("h%d.test", i%100), netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}))
	}
}
