# fqdn-egress

FQDN-based egress firewall for Linux. One daemon that enforces "this machine
may only talk to these domain names" using nftables and a built-in DNS
forwarding proxy. No MITM, no proxy certificates, no per-application setup.

How it works: applications resolve names through the daemon. Allowed names
are forwarded to the real resolver and the answered IPs are pinned into an
nftables set for the duration of their DNS TTL. Everything else -- unknown
names, raw IPs, other resolvers -- hits a default-drop chain.

Two modes:

- `output` -- police this machine's own outbound traffic (servers, CI
  runners, build boxes)
- `forward` -- police traffic routed through this machine (VM taps, bridges)

Status: early development. `check` works; `run` is not implemented yet.

## Quick start

```
fqdn-egress check -config contrib/example-config.yaml
```

More once `run` lands.
