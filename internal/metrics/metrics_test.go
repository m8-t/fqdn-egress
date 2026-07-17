package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestScrape(t *testing.T) {
	m := New(func() float64 { return 3 }, func() float64 { return 12 })
	m.Query("allowed")
	m.Query("allowed")
	m.Query("denied")
	m.Upstream(42 * time.Millisecond)
	m.Reload()

	out := scrape(t, m)
	for _, want := range []string{
		`fqdn_egress_queries_total{verdict="allowed"} 2`,
		`fqdn_egress_queries_total{verdict="denied"} 1`,
		`fqdn_egress_queries_total{verdict="error"} 0`,
		"fqdn_egress_pinned_ips 3",
		"fqdn_egress_allowlist_entries 12",
		"fqdn_egress_allowlist_reloads_total 1",
		"fqdn_egress_upstream_seconds_count 1",
		"go_goroutines",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scrape missing %q", want)
		}
	}
}
