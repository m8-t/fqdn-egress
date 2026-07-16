package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/m8-t/fqdn-egress/internal/allowlist"
	"github.com/m8-t/fqdn-egress/internal/config"
	"github.com/m8-t/fqdn-egress/internal/dnsproxy"
	"github.com/m8-t/fqdn-egress/internal/nft"
)

var version = "dev"

const defaultConfig = "/etc/fqdn-egress/config.yaml"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "check":
		err = check(args)
	case "status":
		err = status()
	case "flush":
		err = flush()
	case "run":
		err = run(args)
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fqdn-egress:", err)
		os.Exit(1)
	}
}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath := configFlag(fs)
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	list, err := allowlist.Load(cfg.Allowlist)
	if err != nil {
		return err
	}

	fmt.Printf("config:    %s\n", *cfgPath)
	fmt.Printf("mode:      %s\n", cfg.Mode)
	if cfg.Mode == "forward" {
		fmt.Printf("interfaces: %v\n", cfg.Interfaces)
	}
	fmt.Printf("listen:    %s\n", cfg.Listen)
	fmt.Printf("upstream:  %s\n", cfg.Upstream)
	fmt.Printf("allowlist: %s (%d entries)\n", cfg.Allowlist, list.Len())
	fmt.Printf("carveouts: %d\n", len(cfg.Carveouts))
	fmt.Println("ok")
	return nil
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := configFlag(fs)
	var debug bool
	fs.BoolVar(&debug, "debug", false, "log at debug level")
	fs.BoolVar(&debug, "d", false, "shorthand for -debug")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	list, err := allowlist.Load(cfg.Allowlist)
	if err != nil {
		return err
	}

	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	m, err := nft.New()
	if err != nil {
		return err
	}
	rs, err := ruleset(cfg)
	if err != nil {
		return err
	}
	if err := m.Install(rs); err != nil {
		return err
	}
	defer m.Teardown()

	p := dnsproxy.New(dnsproxy.Config{
		Listen:   cfg.Listen,
		Upstream: cfg.Upstream,
		Answer:   cfg.Answer,
		MinTTL:   time.Duration(cfg.TTL.Min),
		MaxTTL:   time.Duration(cfg.TTL.Max),
	}, list, m, log)
	if err := p.Listen(); err != nil {
		return err
	}
	defer p.Shutdown()

	errc := make(chan error, 1)
	go func() { errc <- p.Serve() }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	log.Info("running", "mode", cfg.Mode, "listen", cfg.Listen,
		"upstream", cfg.Upstream, "allowlist entries", list.Len())

	for {
		select {
		case err := <-errc:
			return err
		case s := <-sig:
			if s == syscall.SIGHUP {
				l, err := allowlist.Load(cfg.Allowlist)
				if err != nil {
					log.Error("allowlist reload failed, keeping old list", "err", err)
					continue
				}
				p.SetAllowlist(l)
				log.Info("allowlist reloaded", "entries", l.Len())
				continue
			}
			log.Info("shutting down", "signal", s.String())
			return nil
		}
	}
}

// ruleset translates the config into what nft.Install expects.
func ruleset(cfg config.Config) (nft.Ruleset, error) {
	rs := nft.Ruleset{
		Mode:       cfg.Mode,
		Interfaces: cfg.Interfaces,
		LogPrefix:  cfg.LogPrefix,
		DaemonUID:  -1,
	}
	for _, co := range cfg.Carveouts {
		prefix, err := netip.ParsePrefix(co.CIDR)
		if err != nil {
			return rs, fmt.Errorf("carveout %q: %w", co.CIDR, err)
		}
		rs.Carveouts = append(rs.Carveouts, nft.Carveout{
			Prefix: prefix, Proto: co.Proto, Port: co.Port,
		})
	}

	// The daemon's own upstream queries must escape the drop chain. A
	// dedicated non-root user gets a skuid exemption; running as root
	// that would exempt far too much, so carve out the resolver instead.
	if uid := os.Getuid(); uid != 0 {
		rs.DaemonUID = uid
		return rs, nil
	}
	host, _, err := net.SplitHostPort(cfg.Upstream)
	if err != nil {
		return rs, fmt.Errorf("upstream: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return rs, fmt.Errorf("upstream %q: %w", host, err)
	}
	for _, proto := range []string{"udp", "tcp"} {
		rs.Carveouts = append(rs.Carveouts, nft.Carveout{
			Prefix: netip.PrefixFrom(ip, ip.BitLen()), Proto: proto, Port: 53,
		})
	}
	return rs, nil
}

func status() error {
	m, err := nft.New()
	if err != nil {
		return err
	}
	entries, err := m.Entries()
	if err != nil {
		return fmt.Errorf("reading set (is the ruleset installed?): %w", err)
	}
	if len(entries) == 0 {
		fmt.Println("no pinned IPs")
		return nil
	}
	fmt.Printf("%-18s %s\n", "IP", "EXPIRES")
	for _, e := range entries {
		fmt.Printf("%-18s %s\n", e.IP, e.Expires)
	}
	return nil
}

func flush() error {
	m, err := nft.New()
	if err != nil {
		return err
	}
	if err := m.FlushSet(); err != nil {
		return fmt.Errorf("flushing set (is the ruleset installed?): %w", err)
	}
	fmt.Println("pinned IPs cleared")
	return nil
}

func configFlag(fs *flag.FlagSet) *string {
	var path string
	fs.StringVar(&path, "config", defaultConfig, "path to config file")
	fs.StringVar(&path, "c", defaultConfig, "shorthand for -config")
	return &path
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: fqdn-egress <command> [flags]

commands:
  run      start the daemon (ruleset + DNS proxy)
  check    validate config and allowlist, then exit
  status   show currently pinned IPs
  flush    clear pinned IPs
  version  print version

flags:
  -c, -config path   config file (default `+defaultConfig+`)
  -d, -debug         debug logging (run only)
`)
}
