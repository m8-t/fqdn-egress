// Package metrics exposes the daemon's counters on a Prometheus endpoint.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	reg      *prometheus.Registry
	queries  *prometheus.CounterVec
	upstream prometheus.Histogram
	reloads  prometheus.Counter
}

// New builds the registry. The two callbacks are read on every scrape;
// they may return -1 when the value is unavailable.
func New(pinnedIPs, allowlistEntries func() float64) *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fqdn_egress_queries_total",
			Help: "DNS queries handled, by verdict.",
		}, []string{"verdict"}),
		upstream: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "fqdn_egress_upstream_seconds",
			Help:    "Upstream resolver round-trip time.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms .. ~2s
		}),
		reloads: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "fqdn_egress_allowlist_reloads_total",
			Help: "Successful allowlist reloads.",
		}),
	}
	m.reg.MustRegister(
		m.queries, m.upstream, m.reloads,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fqdn_egress_pinned_ips",
			Help: "IPs currently pinned in the nftables set.",
		}, pinnedIPs),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "fqdn_egress_allowlist_entries",
			Help: "Entries in the active allowlist.",
		}, allowlistEntries),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	for _, v := range []string{"allowed", "denied", "error"} {
		m.queries.WithLabelValues(v)
	}
	return m
}

func (m *Metrics) Query(verdict string) {
	m.queries.WithLabelValues(verdict).Inc()
}

func (m *Metrics) Upstream(rtt time.Duration) {
	m.upstream.Observe(rtt.Seconds())
}

func (m *Metrics) Reload() {
	m.reloads.Inc()
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
