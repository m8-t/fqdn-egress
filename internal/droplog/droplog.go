// Package droplog subscribes to the nflog group the drop rule logs to and
// emits one structured line per dropped packet, attributing the
// destination IP to the domain(s) it was last resolved as.
package droplog

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"

	nflog "github.com/florianl/go-nflog/v2"

	"github.com/m8-t/fqdn-egress/internal/names"
)

type Listener struct {
	group uint16
	names *names.Table
	log   *slog.Logger
}

func New(group uint16, t *names.Table, log *slog.Logger) *Listener {
	return &Listener{group: group, names: t, log: log}
}

// Run consumes the nflog group until ctx is cancelled.
func (l *Listener) Run(ctx context.Context) error {
	nf, err := nflog.Open(&nflog.Config{
		Group:    l.group,
		Copymode: nflog.CopyPacket,
	})
	if err != nil {
		return fmt.Errorf("nflog group %d: %w", l.group, err)
	}
	defer nf.Close()

	err = nf.RegisterWithErrorFunc(ctx, l.handle, func(err error) int {
		if ctx.Err() == nil {
			l.log.Error("nflog receive", "err", err)
		}
		return 0
	})
	if err != nil {
		return fmt.Errorf("nflog register: %w", err)
	}
	<-ctx.Done()
	return nil
}

func (l *Listener) handle(a nflog.Attribute) int {
	if a.Payload == nil {
		return 0
	}
	pkt, ok := parseV4(*a.Payload)
	if !ok {
		return 0
	}
	attrs := []any{
		"src", pkt.src, "dst", pkt.dst,
		"proto", pkt.protoName(), "dport", pkt.dport,
	}
	if resolved := l.names.Lookup(pkt.dst); len(resolved) > 0 {
		attrs = append(attrs, "resolved_as", resolved)
	} else {
		attrs = append(attrs, "resolved_as", "never (direct IP?)")
	}
	l.log.Warn("egress blocked", attrs...)
	return 0
}

type packet struct {
	src, dst netip.Addr
	proto    byte
	dport    uint16
}

func (p packet) protoName() string {
	switch p.proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	}
	return fmt.Sprintf("%d", p.proto)
}

func parseV4(b []byte) (packet, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return packet{}, false
	}
	var p packet
	p.proto = b[9]
	p.src, _ = netip.AddrFromSlice(b[12:16])
	p.dst, _ = netip.AddrFromSlice(b[16:20])
	ihl := int(b[0]&0x0f) * 4
	if (p.proto == 6 || p.proto == 17) && len(b) >= ihl+4 {
		p.dport = binary.BigEndian.Uint16(b[ihl+2 : ihl+4])
	}
	return p, true
}
