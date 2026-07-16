// Package nft owns the kernel side: an inet table with a default-drop
// chain and the timed set of allowed destination IPs.
package nft

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	tableName = "fqdn-egress"
	chainName = "egress"
	setName   = "allowed_v4"
)

// Ruleset describes what Install writes to the kernel.
type Ruleset struct {
	Mode       string
	Interfaces []string // forward mode only
	Carveouts  []Carveout
	LogPrefix  string
	// DaemonUID >= 0 adds a skuid accept so the daemon's own upstream
	// queries are not caught by its own drop chain (output mode).
	DaemonUID int
}

type Carveout struct {
	Prefix netip.Prefix
	Proto  string
	Port   uint16
}

type Entry struct {
	IP      netip.Addr
	Expires time.Duration
}

type Manager struct {
	conn  *nftables.Conn
	table *nftables.Table
	set   *nftables.Set
}

func New() (*Manager, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("netlink: %w", err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
	return &Manager{
		conn:  conn,
		table: table,
		set: &nftables.Set{
			Table:      table,
			Name:       setName,
			KeyType:    nftables.TypeIPAddr,
			HasTimeout: true,
		},
	}, nil
}

// Install replaces any previous fqdn-egress table with a fresh one:
// timed set, default-drop chain, and the mode's rules, in one batch.
func (m *Manager) Install(rs Ruleset) error {
	if rs.Mode != "output" {
		return fmt.Errorf("mode %q not implemented", rs.Mode)
	}
	if err := m.Teardown(); err != nil {
		return err
	}

	m.conn.AddTable(m.table)
	if err := m.conn.AddSet(m.set, nil); err != nil {
		return fmt.Errorf("add set: %w", err)
	}
	policy := nftables.ChainPolicyDrop
	chain := m.conn.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    m.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	for _, exprs := range m.outputRules(rs) {
		m.conn.AddRule(&nftables.Rule{Table: m.table, Chain: chain, Exprs: exprs})
	}
	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("install ruleset: %w", err)
	}
	return nil
}

// Teardown removes the table if it exists.
func (m *Manager) Teardown() error {
	tables, err := m.conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == tableName {
			m.conn.DelTable(t)
			if err := m.conn.Flush(); err != nil {
				return fmt.Errorf("delete table: %w", err)
			}
			return nil
		}
	}
	return nil
}

// Pin makes ip reachable for ttl.
func (m *Manager) Pin(ip netip.Addr, ttl time.Duration) error {
	if !ip.Is4() {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}
	key := ip.As4()
	err := m.conn.SetAddElements(m.set, []nftables.SetElement{
		{Key: key[:], Timeout: ttl},
	})
	if err != nil {
		return err
	}
	return m.conn.Flush()
}

// Entries returns the currently pinned IPs with their remaining lifetime.
func (m *Manager) Entries() ([]Entry, error) {
	elems, err := m.conn.GetSetElements(m.set)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(elems))
	for _, e := range elems {
		ip, ok := netip.AddrFromSlice(e.Key)
		if !ok {
			continue
		}
		entries = append(entries, Entry{IP: ip, Expires: e.Expires.Round(time.Second)})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].IP.Less(entries[j].IP)
	})
	return entries, nil
}

// FlushSet drops all pinned IPs but leaves the ruleset in place.
func (m *Manager) FlushSet() error {
	m.conn.FlushSet(m.set)
	return m.conn.Flush()
}

// outputRules builds the output-mode chain, in match order:
// loopback, established, daemon exemption, carveouts, resolver-dodging
// reject, allowed set, rate-limited log. Chain policy drops the rest.
func (m *Manager) outputRules(rs Ruleset) [][]expr.Any {
	var rules [][]expr.Any

	rules = append(rules, []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")},
		&expr.Verdict{Kind: expr.VerdictAccept},
	})

	rules = append(rules, []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	})

	if rs.DaemonUID >= 0 {
		rules = append(rules, []expr.Any{
			&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(rs.DaemonUID))},
			&expr.Verdict{Kind: expr.VerdictAccept},
		})
	}

	for _, co := range rs.Carveouts {
		rules = append(rules, carveoutRule(co))
	}

	// No talking to other resolvers: reject any :53 not already accepted.
	for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		rules = append(rules, []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(53)},
			&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH},
		})
	}

	rules = append(rules, append(matchDaddrIPv4(),
		&expr.Lookup{SourceRegister: 1, SetName: m.set.Name, SetID: m.set.ID},
		&expr.Verdict{Kind: expr.VerdictAccept},
	))

	if rs.LogPrefix != "" {
		rules = append(rules, []expr.Any{
			&expr.Limit{Type: expr.LimitTypePkts, Rate: 10, Unit: expr.LimitTimeMinute, Burst: 5},
			&expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte(rs.LogPrefix)},
		})
	}

	return rules
}

func carveoutRule(co Carveout) []expr.Any {
	network := co.Prefix.Masked().Addr().As4()
	mask := net.CIDRMask(co.Prefix.Bits(), 32)

	exprs := append(matchDaddrIPv4(),
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           mask,
			Xor:            []byte{0, 0, 0, 0},
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network[:]},
	)
	if co.Proto != "" {
		proto := byte(unix.IPPROTO_TCP)
		if co.Proto == "udp" {
			proto = unix.IPPROTO_UDP
		}
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		)
		if co.Port != 0 {
			exprs = append(exprs,
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(co.Port)},
			)
		}
	}
	return append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
}

// matchDaddrIPv4 loads the IPv4 destination address into register 1.
// The nfproto guard is required in an inet table before touching the
// network header (nft(8) inserts the same dependency implicitly).
func matchDaddrIPv4() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
	}
}

func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}
