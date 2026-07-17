#!/bin/bash
# End-to-end test in throwaway network namespaces: a client ns runs the
# daemon, a server ns provides DNS and HTTP. No traffic leaves the box.
#
#   sudo test/integration.sh
set -eu
cd "$(dirname "$0")/.."

if [ "$(id -u)" != 0 ]; then
	echo "needs root: sudo $0" >&2
	exit 1
fi

client=fet-client
server=fet-server
work=$(mktemp -d)
failed=0

cleanup() {
	# shellcheck disable=SC2046
	kill $(jobs -p) 2>/dev/null || true
	ip netns del $client 2>/dev/null || true
	ip netns del $server 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; failed=1; }

# every client command gets its own mount ns (ip netns exec does that), so
# the bind mounts never touch the host. nsswitch is replaced too: nss-resolve
# would bypass resolv.conf and reach the host's systemd-resolved through its
# /run socket, which works across netns.
in_client() {
	ip netns exec $client sh -c "mount --bind $work/resolv.conf /etc/resolv.conf && mount --bind $work/nsswitch.conf /etc/nsswitch.conf && $*"
}

echo "== build"
go build -o "$work/fqdn-egress" ./cmd/fqdn-egress
go build -o "$work/testsrv" ./test/testsrv

echo "== namespaces"
ip netns add $client
ip netns add $server
ip link add veth-c netns $client type veth peer name veth-s netns $server
ip -n $client addr add 10.99.0.2/24 dev veth-c
ip -n $server addr add 10.99.0.1/24 dev veth-s
ip -n $server addr add 10.99.0.3/24 dev veth-s # direct-IP target, never resolved
ip -n $client link set lo up
ip -n $client link set veth-c up
ip -n $server link set lo up
ip -n $server link set veth-s up

ip netns exec $server "$work/testsrv" \
	-dns 10.99.0.1:53 \
	-http 10.99.0.1:80,10.99.0.3:80 \
	-zone allowed.test=10.99.0.1 &
sleep 0.5

echo "allowed.test" > "$work/allowlist.txt"
echo "nameserver 127.0.0.1" > "$work/resolv.conf"
echo "hosts: files dns" > "$work/nsswitch.conf"
cat > "$work/config.yaml" <<EOF
mode: output
listen: 127.0.0.1:53
upstream: 10.99.0.1:53
allowlist: $work/allowlist.txt
metrics_listen: 127.0.0.1:9922
EOF

# before the daemon runs, the direct-IP target must be reachable,
# otherwise the block assertions below prove nothing
if in_client "curl -sf -m 3 http://10.99.0.3/" >/dev/null; then
	pass "baseline: direct IP reachable without daemon"
else
	fail "baseline: direct IP unreachable, test setup broken"
fi

echo "== daemon"
ip netns exec $client "$work/fqdn-egress" run -c "$work/config.yaml" &
daemon=$!
sleep 1

if in_client "curl -sf -m 5 http://allowed.test/" >/dev/null; then
	pass "allowed name works"
else
	fail "allowed name blocked"
fi

if in_client "curl -sf -m 5 http://denied.test/" >/dev/null; then
	fail "non-allowlisted name got through"
else
	pass "non-allowlisted name blocked"
fi

if in_client "curl -sf -m 3 http://10.99.0.3/" >/dev/null; then
	fail "direct IP got through"
else
	pass "direct IP blocked"
fi

if ip netns exec $client "$work/fqdn-egress" status | grep -q 10.99.0.1; then
	pass "status lists pinned IP"
else
	fail "pinned IP missing from status"
fi

if in_client "curl -sf -m 3 http://127.0.0.1:9922/metrics" | grep -q 'fqdn_egress_queries_total{verdict="denied"} [1-9]'; then
	pass "metrics endpoint counts verdicts"
else
	fail "metrics endpoint missing or wrong counts"
fi

echo "== teardown"
kill -TERM $daemon
wait $daemon || true

if ip netns exec $client "$work/fqdn-egress" status >/dev/null 2>&1; then
	fail "ruleset still installed after shutdown"
else
	pass "ruleset removed on shutdown"
fi

exit $failed
