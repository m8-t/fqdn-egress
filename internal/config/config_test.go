package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const minimal = `
upstream: 192.168.1.1
allowlist: /etc/fqdn-egress/allowlist.txt
`

func TestLoadMinimal(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mode != "output" {
		t.Errorf("Mode = %q, want output", cfg.Mode)
	}
	if cfg.Listen != "127.0.0.1:53" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.Upstream != "192.168.1.1:53" {
		t.Errorf("Upstream = %q, want port 53 appended", cfg.Upstream)
	}
	if cfg.Answer != "nxdomain" {
		t.Errorf("Answer = %q", cfg.Answer)
	}
	if time.Duration(cfg.TTL.Min) != 30*time.Second || time.Duration(cfg.TTL.Max) != time.Hour {
		t.Errorf("TTL defaults = %v/%v", cfg.TTL.Min, cfg.TTL.Max)
	}
}

func TestLoadFull(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
mode: forward
listen: 172.16.0.1:53
upstream: 172.16.20.70:53
allowlist: /etc/fqdn-egress/allowlist.txt
interfaces: [tap-claude0]
dns_dnat: true
ttl:
  min: 1m
  max: 2h
carveouts:
  - cidr: 172.16.20.80/32
    proto: tcp
    port: 6443
  - cidr: 10.0.0.7
answer: refuse
metrics_listen: 127.0.0.1:9100
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if time.Duration(cfg.TTL.Min) != time.Minute {
		t.Errorf("TTL.Min = %v", cfg.TTL.Min)
	}
	if cfg.Carveouts[1].CIDR != "10.0.0.7/32" {
		t.Errorf("bare IP carveout = %q, want /32 appended", cfg.Carveouts[1].CIDR)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{"bad mode", "mode: both\nupstream: 1.2.3.4\nallowlist: /a", "mode must be"},
		{"forward without interfaces", "mode: forward\nupstream: 1.2.3.4\nallowlist: /a", "interface"},
		{"output with interfaces", "interfaces: [eth0]\nupstream: 1.2.3.4\nallowlist: /a", "forward mode"},
		{"missing allowlist", "upstream: 1.2.3.4", "allowlist"},
		{"missing upstream", "allowlist: /a", "upstream"},
		{"bad upstream", "upstream: not-an-ip\nallowlist: /a", "upstream"},
		{"bad listen", "listen: 300.0.0.1:53\nupstream: 1.2.3.4\nallowlist: /a", "listen"},
		{"ttl max below min", "upstream: 1.2.3.4\nallowlist: /a\nttl: {min: 1h, max: 1m}", "ttl.max"},
		{"bad answer", "answer: drop\nupstream: 1.2.3.4\nallowlist: /a", "answer"},
		{"bad carveout cidr", "upstream: 1.2.3.4\nallowlist: /a\ncarveouts: [{cidr: nope}]", "cidr"},
		{"carveout port without proto", "upstream: 1.2.3.4\nallowlist: /a\ncarveouts: [{cidr: 10.0.0.1, port: 80}]", "proto"},
		{"unknown field", "upstream: 1.2.3.4\nallowlist: /a\nallowlst: typo", "field"},
		{"dnat in output mode", "dns_dnat: true\nupstream: 1.2.3.4\nallowlist: /a", "dns_dnat"},
		{"dnat with wildcard listen", "mode: forward\ninterfaces: [tap0]\ndns_dnat: true\nlisten: 0.0.0.0:53\nupstream: 1.2.3.4\nallowlist: /a", "dns_dnat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.content))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error")
	}
}
