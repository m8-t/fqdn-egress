// Package names remembers which FQDNs resolved to which IPs, so a dropped
// packet's destination can be attributed to the domain a client was
// actually trying to reach. Entries outlive the nft pins on purpose:
// attribution is most useful exactly when a pin has expired.
package names

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	retention = 24 * time.Hour
	maxIPs    = 8192
)

type Table struct {
	mu  sync.RWMutex
	ips map[netip.Addr]map[string]time.Time
}

func New() *Table {
	return &Table{ips: make(map[netip.Addr]map[string]time.Time)}
}

// Record notes that name just resolved to ip.
func (t *Table) Record(name string, ip netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.ips[ip]
	if !ok {
		if len(t.ips) >= maxIPs {
			t.evictOldest()
		}
		m = make(map[string]time.Time)
		t.ips[ip] = m
	}
	m[name] = time.Now()
}

// Lookup returns the names ip has resolved as, most recent first.
func (t *Table) Lookup(ip netip.Addr) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	m := t.ips[ip]
	if len(m) == 0 {
		return nil
	}
	cutoff := time.Now().Add(-retention)
	names := make([]string, 0, len(m))
	for name, seen := range m {
		if seen.After(cutoff) {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return m[names[i]].After(m[names[j]])
	})
	return names
}

// evictOldest drops the IP whose most recent resolution is the stalest.
// Called with the lock held.
func (t *Table) evictOldest() {
	var oldest netip.Addr
	var oldestSeen time.Time
	for ip, m := range t.ips {
		var last time.Time
		for _, seen := range m {
			if seen.After(last) {
				last = seen
			}
		}
		if oldestSeen.IsZero() || last.Before(oldestSeen) {
			oldest, oldestSeen = ip, last
		}
	}
	delete(t.ips, oldest)
}
