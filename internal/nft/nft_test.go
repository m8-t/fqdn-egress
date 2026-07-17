package nft

import (
	"bytes"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The tests below talk to a real kernel and need CAP_NET_ADMIN. Run them
// in an unprivileged namespace:
//
//	unshare -Ur -n go test ./internal/nft/
//
// Without privileges they skip.
func newPrivileged(t *testing.T) *Manager {
	t.Helper()
	m, err := New()
	if err != nil {
		t.Skipf("netlink unavailable: %v", err)
	}
	if _, err := m.conn.ListTablesOfFamily(0); err != nil {
		t.Skipf("need CAP_NET_ADMIN (run under unshare -Ur -n): %v", err)
	}
	return m
}

func testRuleset() Ruleset {
	return Ruleset{
		Mode:      "output",
		LogPrefix: "test-blocked: ",
		DaemonUID: 1000,
		Carveouts: []Carveout{
			{Prefix: netip.MustParsePrefix("172.16.20.80/32"), Proto: "tcp", Port: 6443},
			{Prefix: netip.MustParsePrefix("10.0.0.0/8")},
		},
	}
}

func TestInstallTeardown(t *testing.T) {
	m := newPrivileged(t)
	if err := m.Install(testRuleset()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	defer m.Teardown()

	out := nftList(t)
	for _, want := range []string{
		"table inet fqdn-egress",
		"set allowed_v4",
		"timeout",
		"policy drop",
		`oifname "lo" accept`,
		"ct state established,related accept",
		"meta skuid 1000 accept",
		"ip daddr 172.16.20.80 tcp dport 6443 accept",
		"ip daddr 10.0.0.0/8 accept",
		"reject",
		"@allowed_v4 accept",
		`log prefix "test-blocked: "`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset missing %q\n%s", want, out)
		}
	}

	if err := m.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if out := nftList(t); strings.Contains(out, "fqdn-egress") {
		t.Errorf("table still present after Teardown:\n%s", out)
	}
	// idempotent on a missing table
	if err := m.Teardown(); err != nil {
		t.Fatalf("second Teardown: %v", err)
	}
}

func TestInstallTwice(t *testing.T) {
	m := newPrivileged(t)
	defer m.Teardown()
	for i := 0; i < 2; i++ {
		if err := m.Install(testRuleset()); err != nil {
			t.Fatalf("Install #%d: %v", i+1, err)
		}
	}
	if n := strings.Count(nftList(t), "table inet fqdn-egress"); n != 1 {
		t.Errorf("found %d tables, want 1", n)
	}
}

func TestPinEntriesFlush(t *testing.T) {
	m := newPrivileged(t)
	if err := m.Install(testRuleset()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	defer m.Teardown()

	for _, ip := range []string{"140.82.121.4", "1.1.1.1"} {
		if err := m.Pin(netip.MustParseAddr(ip), time.Minute); err != nil {
			t.Fatalf("Pin(%s): %v", ip, err)
		}
	}

	entries, err := m.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].IP.String() != "1.1.1.1" {
		t.Errorf("entries not sorted: %v", entries)
	}
	for _, e := range entries {
		if e.Expires <= 0 || e.Expires > time.Minute {
			t.Errorf("%s: implausible expiry %v", e.IP, e.Expires)
		}
	}

	if err := m.FlushSet(); err != nil {
		t.Fatalf("FlushSet: %v", err)
	}
	entries, err = m.Entries()
	if err != nil {
		t.Fatalf("Entries after flush: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("set not empty after flush: %v", entries)
	}
}

func TestPinRejectsIPv6(t *testing.T) {
	m := newPrivileged(t)
	if err := m.Install(testRuleset()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	defer m.Teardown()
	if err := m.Pin(netip.MustParseAddr("2606:4700::1111"), time.Minute); err == nil {
		t.Error("expected error pinning an IPv6 address")
	}
}

func TestInstallForward(t *testing.T) {
	m := newPrivileged(t)
	rs := Ruleset{
		Mode:       "forward",
		Interfaces: []string{"tap0", "tap1"},
		LogPrefix:  "test-blocked: ",
		DaemonUID:  -1,
		DNSDNat:    true,
		ProxyAddr:  netip.MustParseAddrPort("172.16.0.1:53"),
	}
	if err := m.Install(rs); err != nil {
		t.Fatalf("Install: %v", err)
	}
	defer m.Teardown()

	out := nftList(t)
	for _, want := range []string{
		"hook forward",
		"policy drop",
		`iifname != @ifaces accept`,
		"ct state established,related accept",
		"@allowed_v4 accept",
		"hook prerouting",
		"udp dport 53 dnat",
		"tcp dport 53 dnat",
		"172.16.0.1:53",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset missing %q\n%s", want, out)
		}
	}
}

func TestInstallForwardNoDNat(t *testing.T) {
	m := newPrivileged(t)
	rs := Ruleset{Mode: "forward", Interfaces: []string{"tap0"}, DaemonUID: -1}
	if err := m.Install(rs); err != nil {
		t.Fatalf("Install: %v", err)
	}
	defer m.Teardown()
	if out := nftList(t); strings.Contains(out, "prerouting") {
		t.Errorf("unexpected nat chain without dns_dnat:\n%s", out)
	}
}

func TestInstallUnknownMode(t *testing.T) {
	m := newPrivileged(t)
	if err := m.Install(Ruleset{Mode: "sideways", DaemonUID: -1}); err == nil {
		m.Teardown()
		t.Fatal("expected error for unknown mode")
	}
}

func nftList(t *testing.T) string {
	t.Helper()
	var out bytes.Buffer
	cmd := exec.Command("nft", "list", "ruleset")
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("nft list ruleset: %v\n%s", err, out.String())
	}
	return out.String()
}
