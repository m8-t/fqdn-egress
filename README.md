# fqdn-egress

FQDN-based egress firewall for Linux. One daemon that enforces "this machine
may only talk to these domain names" using nftables and a built-in DNS
forwarding proxy. No MITM, no proxy certificates, no per-application setup.

Typical use: locking a server, CI runner, or build box down to the handful
of domains it actually needs, so a compromised dependency or leaked token
cannot phone home.

```
# /etc/fqdn-egress/allowlist.txt
github.com
*.github.com
proxy.golang.org
registry.npmjs.org
```

## How it works

Applications resolve names through the daemon. Allowed names are forwarded
to the real resolver and the answered IPs are pinned into an nftables set
for the duration of their DNS TTL. Everything else -- unknown names, raw
IPs, other resolvers -- hits a default-drop chain.

```
 app ──── DNS query ────> proxy ── allowed? ──> upstream resolver
                            │                        │
                            │ no                     │ A records
                            v                        v
                         NXDOMAIN            pin IP (TTL) ──> nft set
                                                              │
 app ──── connect ───────────────────── daddr in set? ────────┘
                                          │        │
                                         yes       no
                                        accept    drop
```

A client that resolves elsewhere (DoH, hardcoded IPs) still cannot connect:
the verdict falls to the nftables set, and only proxy-resolved IPs are in it.
Direct port 53 to anything but the proxy is rejected.

Two modes, same engine:

- `output` -- police this machine's own outbound traffic via the output
  hook. The default and the common case.
- `forward` -- police traffic routed through this machine (VM taps,
  bridges) via the forward hook, scoped to configured interfaces.
  Optionally DNAT guest port 53 to the proxy so guests with hardcoded
  resolvers still resolve through the allowlist.

The project grew out of a microVM sandbox that needed exactly this and did
it with dnsmasq's nftset option plus a render script. fqdn-egress replaces
that combo with one static binary; see the comparison below.

## Quick start

```
go install github.com/m8-t/fqdn-egress/cmd/fqdn-egress@latest
cp contrib/example-config.yaml /etc/fqdn-egress/config.yaml   # edit: upstream, allowlist
fqdn-egress check
sudo fqdn-egress run
```

Point the system resolver at the proxy (output mode), e.g. plain
`/etc/resolv.conf`:

```
nameserver 127.0.0.1
```

or a systemd-resolved drop-in (`/etc/systemd/resolved.conf.d/fqdn-egress.conf`):

```
[Resolve]
DNS=127.0.0.1
DNSStubListener=no
```

For a permanent install use the hardened unit in `contrib/`, which runs the
daemon as a dedicated non-root user with `CAP_NET_ADMIN`:

```
cp contrib/fqdn-egress.sysusers /usr/lib/sysusers.d/fqdn-egress.conf && systemd-sysusers
cp contrib/fqdn-egress.service /etc/systemd/system/ && systemctl enable --now fqdn-egress
```

## Configuration

One YAML file, one flat allowlist. `contrib/example-config.yaml` documents
every knob:

| key | default | |
|---|---|---|
| `mode` | `output` | `output` or `forward` |
| `listen` | `127.0.0.1:53` | proxy address; tap/bridge IP in forward mode |
| `upstream` | - | resolver queries are forwarded to |
| `allowlist` | - | path to the allowlist file |
| `interfaces` | - | forward mode: interfaces to police |
| `dns_dnat` | `false` | forward mode: redirect guest :53 to the proxy |
| `ttl.min`, `ttl.max` | `30s`, `1h` | clamp for how long resolved IPs stay pinned |
| `carveouts` | - | static CIDR(+proto+port) accepts, for IP-only destinations |
| `answer` | `nxdomain` | reply for denied names: `nxdomain` or `refuse` |
| `log_prefix` | `fqdn-egress-blocked: ` | kernel log prefix for dropped packets |
| `metrics_listen` | off | Prometheus endpoint address |

Allowlist: one name per line, `#` comments, `*.example.com` wildcards
(matches subdomains, not the apex). Reload with SIGHUP; pinned IPs and the
ruleset stay in place.

```
fqdn-egress run     start the daemon
fqdn-egress check   validate config and allowlist, no root needed
fqdn-egress status  show pinned IPs with remaining TTL
fqdn-egress flush   clear pinned IPs
```

Denied and dropped traffic is observable in three places: structured logs
(denied queries), `journalctl -k | grep fqdn-egress-blocked` (dropped
packets, rate-limited), and `/metrics` (queries by verdict, upstream
latency, pinned set size).

## Threat model

What it stops: egress to any destination whose name is not on the
allowlist, including direct-to-IP connections and DNS exfiltration via
alternative resolvers.

What it does not stop:

- Content-level abuse of allowed destinations. If `github.com` is allowed,
  data can be pushed to any repository on it. This is an L3/L4 control,
  not L7 inspection.
- A client resolving over DoH/DoT to an allowed host learns other IPs but
  still cannot connect to them; the control holds, but expect NXDOMAIN
  noise in its logs rather than clean failures.

IPv6 is answered empty (clients fall back to v4) and not pinned; a v6
default-drop is on the roadmap before v6 answers are.

## Compared to the dnsmasq nftset trick

dnsmasq can pin resolved IPs into an nft set (`--nftset`), which is the
same core idea and works. In practice it needs a second tool to render
`nftset=/name/...` lines from an allowlist, a hand-written companion
ruleset, and careful ordering between the two; wildcard semantics are
dnsmasq's, and there is no status/flush tooling or metrics. fqdn-egress is
that whole stack in one binary with one config file.

Heavier alternatives (Cilium DNS policies, OPNsense aliases, MITM proxies)
solve broader problems; if you just need "this box talks to these names",
they are a lot of machinery.

## Development

```
go test ./...                            # unit tests
unshare -Ur -n go test ./internal/nft/   # kernel-facing tests, unprivileged netns
sudo test/integration.sh                 # end-to-end, output mode
sudo test/integration-forward.sh         # end-to-end, forward mode + dnat
```

The integration tests build throwaway network namespaces and never send
traffic off the machine.

## License

WTFPL
