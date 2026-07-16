// Fixture for the integration test: a DNS server with a canned zone plus
// HTTP listeners that answer 200 to everything.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

func main() {
	dnsAddr := flag.String("dns", "", "udp address for the dns server")
	httpAddrs := flag.String("http", "", "comma-separated http addresses")
	zone := flag.String("zone", "", "comma-separated name=ipv4 records")
	flag.Parse()

	records := make(map[string]string)
	for _, rec := range strings.Split(*zone, ",") {
		name, ip, ok := strings.Cut(rec, "=")
		if !ok {
			log.Fatalf("bad zone record %q", rec)
		}
		records[dns.Fqdn(name)] = ip
	}

	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		q := req.Question[0]
		if ip, ok := records[q.Name]; ok && q.Qtype == dns.TypeA {
			m.SetReply(req)
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, ip))
			if err != nil {
				log.Fatal(err)
			}
			m.Answer = []dns.RR{rr}
		} else {
			m.SetRcode(req, dns.RcodeNameError)
		}
		w.WriteMsg(m)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	for _, addr := range strings.Split(*httpAddrs, ",") {
		go func() { log.Fatal(http.ListenAndServe(addr, nil)) }()
	}

	srv := &dns.Server{Addr: *dnsAddr, Net: "udp"}
	log.Fatal(srv.ListenAndServe())
}
