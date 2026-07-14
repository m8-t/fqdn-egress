package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/m8-t/fqdn-egress/internal/allowlist"
	"github.com/m8-t/fqdn-egress/internal/config"
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
	case "run", "status", "flush":
		err = fmt.Errorf("%s: not implemented yet", cmd)
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
	cfgPath := fs.String("config", defaultConfig, "path to config file")
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

func usage() {
	fmt.Fprint(os.Stderr, `usage: fqdn-egress <command> [flags]

commands:
  run      start the daemon (ruleset + DNS proxy)
  check    validate config and allowlist, then exit
  status   show currently pinned IPs
  flush    clear pinned IPs
  version  print version

flags:
  -config path   config file (default `+defaultConfig+`)
`)
}
