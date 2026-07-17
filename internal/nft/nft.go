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
	Interfaces []string // forward mode: police traffic entering on these
	Carveouts  []Carveout
	LogPrefix  string
	// DaemonUID >= 0 adds a skuid accept so the daemon's own upstream
	// queries are not caught by its own drop chain (output mode).
	DaemonUID int
	// DNSDNat redirects :53 from the policed interfaces to ProxyAddr,
	// so guests with a hardcoded resolver still talk to the proxy.
	DNSDNat   bool
	ProxyAddr netip.AddrPort
	// NFLogGroup > 0 sends dropped packets to that nflog group instead
	// of the kernel log, so the daemon can log them with DNS context.
	NFLogGroup int
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
	if err := m.Teardown(); err != nil {
		return err
	}

	m.conn.AddTable(m.table)
	if err := m.conn.AddSet(m.set, nil); err != nil {
		return fmt.Errorf("add set: %w", err)
	}

	var hook *nftables.ChainHook
	var rules [][]expr.Any
	switch rs.Mode {
	case "output":
		hook = nftables.ChainHookOutput
		rules = m.outputRules(rs)
	case "forward":
		hook = nftables.ChainHookForward
		ifaces, err := m.addIfaceSet(rs.Interfaces)
		if err != nil {
			return err
		}
		rules = m.forwardRules(rs, ifaces)
		if rs.DNSDNat {
			if err := m.addDNSDNat(rs, ifaces); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("mode %q not implemented", rs.Mode)
	}

	policy := nftables.ChainPolicyDrop
	chain := m.conn.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    m.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  hook,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	for _, exprs := range rules {
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
// loopback, established, daemon exemption, then the shared tail.
// Chain policy drops the rest.
func (m *Manager) outputRules(rs Ruleset) [][]expr.Any {
	rules := [][]expr.Any{{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname("lo")},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
	rules = append(rules, established())

	if rs.DaemonUID >= 0 {
		rules = append(rules, []expr.Any{
			&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(rs.DaemonUID))},
			&expr.Verdict{Kind: expr.VerdictAccept},
		})
	}

	return append(rules, m.policedRules(rs)...)
}

// forwardRules polices only traffic entering on the configured
// interfaces; anything else is waved through up front because the chain
// policy drops.
func (m *Manager) forwardRules(rs Ruleset, ifaces *nftables.Set) [][]expr.Any {
	rules := [][]expr.Any{{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: ifaces.Name, SetID: ifaces.ID, Invert: true},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
	rules = append(rules, established())
	return append(rules, m.policedRules(rs)...)
}

// policedRules is the tail both modes share: carveouts, resolver-dodging
// reject, allowed set, rate-limited log.
func (m *Manager) policedRules(rs Ruleset) [][]expr.Any {
	var rules [][]expr.Any

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

	switch {
	case rs.NFLogGroup > 0:
		rules = append(rules, []expr.Any{
			&expr.Limit{Type: expr.LimitTypePkts, Rate: 10, Unit: expr.LimitTimeMinute, Burst: 5},
			&expr.Log{Key: 1 << unix.NFTA_LOG_GROUP, Group: uint16(rs.NFLogGroup)},
		})
	case rs.LogPrefix != "":
		rules = append(rules, []expr.Any{
			&expr.Limit{Type: expr.LimitTypePkts, Rate: 10, Unit: expr.LimitTimeMinute, Burst: 5},
			&expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte(rs.LogPrefix)},
		})
	}

	return rules
}

func established() []expr.Any {
	return []expr.Any{
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
	}
}

func (m *Manager) addIfaceSet(names []string) (*nftables.Set, error) {
	s := &nftables.Set{
		Table:    m.table,
		Name:     "ifaces",
		KeyType:  nftables.TypeIFName,
		Constant: true,
	}
	elems := make([]nftables.SetElement, len(names))
	for i, n := range names {
		elems[i] = nftables.SetElement{Key: ifname(n)}
	}
	if err := m.conn.AddSet(s, elems); err != nil {
		return nil, fmt.Errorf("add interface set: %w", err)
	}
	return s, nil
}

// addDNSDNat rewrites :53 from the policed interfaces to the proxy in
// prerouting, before the forward chain ever sees the packet.
func (m *Manager) addDNSDNat(rs Ruleset, ifaces *nftables.Set) error {
	if !rs.ProxyAddr.IsValid() || !rs.ProxyAddr.Addr().Is4() {
		return fmt.Errorf("dns dnat needs an IPv4 proxy address, got %q", rs.ProxyAddr)
	}
	chain := m.conn.AddChain(&nftables.Chain{
		Name:     "dstnat",
		Table:    m.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})
	addr := rs.ProxyAddr.Addr().As4()
	for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		m.conn.AddRule(&nftables.Rule{Table: m.table, Chain: chain, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Lookup{SourceRegister: 1, SetName: ifaces.Name, SetID: ifaces.ID},
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(53)},
			&expr.Immediate{Register: 1, Data: addr[:]},
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(rs.ProxyAddr.Port())},
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegProtoMin: 2,
				Specified:   true,
			},
		}})
	}
	return nil
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
