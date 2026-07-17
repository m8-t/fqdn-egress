package droplog

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func v4Packet(src, dst string, proto byte, dport uint16) []byte {
	b := make([]byte, 24)
	b[0] = 0x45 // v4, ihl 5
	b[9] = proto
	copy(b[12:16], netip.MustParseAddr(src).AsSlice())
	copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
	binary.BigEndian.PutUint16(b[22:24], dport)
	return b
}

func TestParseV4(t *testing.T) {
	pkt, ok := parseV4(v4Packet("172.16.0.2", "1.1.1.1", 6, 443))
	if !ok {
		t.Fatal("parse failed")
	}
	if pkt.src.String() != "172.16.0.2" || pkt.dst.String() != "1.1.1.1" {
		t.Errorf("addrs = %s -> %s", pkt.src, pkt.dst)
	}
	if pkt.protoName() != "tcp" || pkt.dport != 443 {
		t.Errorf("proto %s dport %d", pkt.protoName(), pkt.dport)
	}
}

func TestParseV4Garbage(t *testing.T) {
	for _, b := range [][]byte{nil, {0x60, 0x00}, make([]byte, 10)} {
		if _, ok := parseV4(b); ok {
			t.Errorf("parsed garbage %v", b)
		}
	}
}

func TestParseV4NoTransportHeader(t *testing.T) {
	b := v4Packet("10.0.0.1", "10.0.0.2", 6, 443)[:20]
	pkt, ok := parseV4(b)
	if !ok {
		t.Fatal("parse failed")
	}
	if pkt.dport != 0 {
		t.Errorf("dport = %d, want 0 for truncated packet", pkt.dport)
	}
}
