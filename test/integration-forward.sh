#!/bin/bash
# Forward-mode end-to-end test: guest ns -> gateway ns (daemon) -> server ns.
# The guest is configured with the server's resolver address on purpose:
# the dns_dnat rule must intercept and redirect it to the proxy.
#
#   sudo test/integration-forward.sh
set -eu
cd "$(dirname "$0")/.."

if [ "$(id -u)" != 0 ]; then
	echo "needs root: sudo $0" >&2
	exit 1
fi

guest=fet-guest
gw=fet-gw
server=fet-server
work=$(mktemp -d)
failed=0

cleanup() {
	# shellcheck disable=SC2046
	kill $(jobs -p) 2>/dev/null || true
	ip netns del "$guest" 2>/dev/null || true
	ip netns del "$gw" 2>/dev/null || true
	ip netns del "$server" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; failed=1; }

in_guest() {
	ip netns exec $guest sh -c "mount --bind $work/resolv.conf /etc/resolv.conf && mount --bind $work/nsswitch.conf /etc/nsswitch.conf && $*"
}

echo "== build"
go build -o "$work/fqdn-egress" ./cmd/fqdn-egress
go build -o "$work/testsrv" ./test/testsrv

echo "== namespaces"
ip netns add $guest
ip netns add $gw
ip netns add $server
ip link add veth-g netns $guest type veth peer name veth-gw0 netns $gw
ip link add veth-gw1 netns $gw type veth peer name veth-s netns $server

ip -n $guest addr add 10.99.1.2/24 dev veth-g
ip -n $gw addr add 10.99.1.1/24 dev veth-gw0
ip -n $gw addr add 10.99.0.2/24 dev veth-gw1
ip -n $server addr add 10.99.0.1/24 dev veth-s
ip -n $server addr add 10.99.0.3/24 dev veth-s # direct-IP target, never resolved

for ns in $guest $gw $server; do
	ip -n "$ns" link set lo up
done
ip -n $guest link set veth-g up
ip -n $gw link set veth-gw0 up
ip -n $gw link set veth-gw1 up
ip -n $server link set veth-s up

ip -n $guest route add default via 10.99.1.1
ip -n $server route add 10.99.1.0/24 via 10.99.0.2
ip netns exec $gw sysctl -qw net.ipv4.ip_forward=1

ip netns exec $server "$work/testsrv" \
	-dns 10.99.0.1:53 \
	-http 10.99.0.1:80,10.99.0.3:80 \
	-zone allowed.test=10.99.0.1 &
sleep 0.5

echo "allowed.test" > "$work/allowlist.txt"
# not the proxy: dnat has to redirect this to 10.99.1.1
echo "nameserver 10.99.0.1" > "$work/resolv.conf"
echo "hosts: files dns" > "$work/nsswitch.conf"
cat > "$work/config.yaml" <<EOF
mode: forward
interfaces: [veth-gw0]
dns_dnat: true
listen: 10.99.1.1:53
upstream: 10.99.0.1:53
allowlist: $work/allowlist.txt
EOF

if in_guest "curl -sf -m 3 http://10.99.0.3/" >/dev/null; then
	pass "baseline: direct IP reachable through gateway without daemon"
else
	fail "baseline: direct IP unreachable, test setup broken"
fi

echo "== daemon"
ip netns exec $gw "$work/fqdn-egress" run -c "$work/config.yaml" &
daemon=$!
sleep 1

if in_guest "curl -sf -m 5 http://allowed.test/" >/dev/null; then
	pass "allowed name works via dnat-intercepted resolver"
else
	fail "allowed name blocked"
fi

if in_guest "curl -sf -m 5 http://denied.test/" >/dev/null; then
	fail "non-allowlisted name got through"
else
	pass "non-allowlisted name blocked"
fi

if in_guest "curl -sf -m 3 http://10.99.0.3/" >/dev/null; then
	fail "direct IP got through"
else
	pass "direct IP blocked"
fi

if ip netns exec $gw "$work/fqdn-egress" status | grep -q 10.99.0.1; then
	pass "status lists pinned IP"
else
	fail "pinned IP missing from status"
fi

echo "== teardown"
kill -TERM $daemon
wait $daemon || true

if ip netns exec $gw "$work/fqdn-egress" status >/dev/null 2>&1; then
	fail "ruleset still installed after shutdown"
else
	pass "ruleset removed on shutdown"
fi

exit $failed
