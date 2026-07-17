package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode          string     `yaml:"mode"`
	Listen        string     `yaml:"listen"`
	Upstream      string     `yaml:"upstream"`
	Allowlist     string     `yaml:"allowlist"`
	Interfaces    []string   `yaml:"interfaces"`
	DNSDNat       bool       `yaml:"dns_dnat"`
	TTL           TTL        `yaml:"ttl"`
	Carveouts     []Carveout `yaml:"carveouts"`
	Answer        string     `yaml:"answer"`
	LogPrefix     string     `yaml:"log_prefix"`
	NFLogGroup    int        `yaml:"nflog_group"`
	MetricsListen string     `yaml:"metrics_listen"`
}

type TTL struct {
	Min Duration `yaml:"min"`
	Max Duration `yaml:"max"`
}

// Carveout is a static accept rule for destinations that need no DNS,
// e.g. a LAN service reached by IP. Port 0 means all ports.
type Carveout struct {
	CIDR  string `yaml:"cidr"`
	Proto string `yaml:"proto"`
	Port  uint16 `yaml:"port"`
}

// Duration wraps time.Duration so YAML values like "30s" parse directly.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func Default() Config {
	return Config{
		Mode:      "output",
		Listen:    "127.0.0.1:53",
		Answer:    "nxdomain",
		LogPrefix: "fqdn-egress-blocked: ",
		TTL: TTL{
			Min: Duration(30 * time.Second),
			Max: Duration(time.Hour),
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) validate() error {
	switch c.Mode {
	case "output":
		if len(c.Interfaces) > 0 {
			return errors.New("interfaces only apply to forward mode")
		}
		if c.DNSDNat {
			return errors.New("dns_dnat only applies to forward mode")
		}
	case "forward":
		if len(c.Interfaces) == 0 {
			return errors.New("forward mode needs at least one interface")
		}
	default:
		return fmt.Errorf("mode must be output or forward, got %q", c.Mode)
	}

	if c.Allowlist == "" {
		return errors.New("allowlist path is required")
	}
	if err := hostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if c.DNSDNat {
		host, _, _ := net.SplitHostPort(c.Listen)
		if ip, _ := netip.ParseAddr(host); ip.IsUnspecified() {
			return errors.New("dns_dnat needs a concrete listen address to redirect to")
		}
	}
	if c.Upstream == "" {
		return errors.New("upstream resolver is required")
	}
	if _, _, err := net.SplitHostPort(c.Upstream); err != nil {
		// bare address: default to port 53
		if ip, perr := netip.ParseAddr(c.Upstream); perr == nil {
			c.Upstream = net.JoinHostPort(ip.String(), "53")
		} else {
			return fmt.Errorf("upstream: %w", err)
		}
	}

	if c.TTL.Min <= 0 {
		return errors.New("ttl.min must be positive")
	}
	if c.TTL.Max < c.TTL.Min {
		return errors.New("ttl.max must be >= ttl.min")
	}

	switch c.Answer {
	case "nxdomain", "refuse":
	default:
		return fmt.Errorf("answer must be nxdomain or refuse, got %q", c.Answer)
	}

	for i := range c.Carveouts {
		if err := c.Carveouts[i].validate(); err != nil {
			return fmt.Errorf("carveout %d: %w", i+1, err)
		}
	}
	if c.NFLogGroup < 0 || c.NFLogGroup > 65535 {
		return fmt.Errorf("nflog_group must be 0-65535, got %d", c.NFLogGroup)
	}
	if c.MetricsListen != "" {
		if err := hostPort(c.MetricsListen); err != nil {
			return fmt.Errorf("metrics_listen: %w", err)
		}
	}
	return nil
}

func (co *Carveout) validate() error {
	if co.CIDR == "" {
		return errors.New("cidr is required")
	}
	if _, err := netip.ParsePrefix(co.CIDR); err != nil {
		// accept a bare IP and treat it as a /32
		ip, perr := netip.ParseAddr(co.CIDR)
		if perr != nil {
			return fmt.Errorf("cidr: %w", err)
		}
		co.CIDR = netip.PrefixFrom(ip, ip.BitLen()).String()
	}
	switch co.Proto {
	case "tcp", "udp":
	case "":
		if co.Port != 0 {
			return errors.New("port needs a proto")
		}
	default:
		return fmt.Errorf("proto must be tcp or udp, got %q", co.Proto)
	}
	return nil
}

func hostPort(s string) error {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("invalid address %q", host)
	}
	return nil
}

func (d Duration) String() string {
	return time.Duration(d).String()
}
