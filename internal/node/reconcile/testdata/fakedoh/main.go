// Command fakedoh is a DNS-over-HTTPS endpoint (RFC 8484) for the integration
// test of the DNS forwarder (dns_integration_test.go). It answers from a zone of
// its own, so that an answer that reaches a container can only have come
// through it:
//
//	www.example.com  A 192.0.2.10
//	big.example.com  A 198.51.100.1 to 198.51.100.40, too much for 512 bytes
//
// and NXDOMAIN for any other name. It prints every question it is asked.
//
//	fakedoh -listen 127.0.0.1:40053 -cert cert.pem -key key.pem
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// bigCount is the number of A records of big.example.com.
const bigCount = 40

func main() {
	listen := flag.String("listen", "127.0.0.1:40053", "the address to listen on")
	cert := flag.String("cert", "", "the certificate, PEM")
	key := flag.String("key", "", "its private key, PEM")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", serve)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("fakedoh: listening on %s", *listen)
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

func serve(w http.ResponseWriter, r *http.Request) {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); r.Method != http.MethodPost || mt != "application/dns-message" {
		http.Error(w, "a POST of application/dns-message, please", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var q dnsmessage.Message
	if err := q.Unpack(body); err != nil || len(q.Questions) != 1 {
		http.Error(w, "not a query with one question", http.StatusBadRequest)
		return
	}
	resp := answer(q)
	wire, err := resp.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("fakedoh: %s %s id %d -> %s, %d records", q.Questions[0].Name, q.Questions[0].Type, q.ID, resp.RCode, len(resp.Answers))
	w.Header().Set("Content-Type", "application/dns-message")
	_, _ = w.Write(wire)
}

func answer(q dnsmessage.Message) dnsmessage.Message {
	qq := q.Questions[0]
	resp := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true},
		Questions: q.Questions,
	}
	a := func(ip string) dnsmessage.Resource {
		return dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()},
		}
	}
	switch strings.ToLower(qq.Name.String()) {
	case "www.example.com.":
		if qq.Type == dnsmessage.TypeA {
			resp.Answers = []dnsmessage.Resource{a("192.0.2.10")}
		}
	case "big.example.com.":
		if qq.Type == dnsmessage.TypeA {
			for i := range bigCount {
				resp.Answers = append(resp.Answers, a(fmt.Sprintf("198.51.100.%d", i+1)))
			}
		}
	default:
		resp.RCode = dnsmessage.RCodeNameError
	}
	return resp
}
