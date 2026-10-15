// Command readycheck polls the real telemt.Driver.Ready until the engine is
// ready or the time is up. It exists for the integration test.
//
// The driver talks to 127.0.0.1, which is the engine's loopback when the agent
// itself runs on the host network, as it does in production. A test process is
// not always on the same network: with Docker Desktop the daemon's "host" is a
// VM, and a container with network mode host is on that VM's loopback, out of
// reach of the test. So the test runs this program in a container of its own on
// the host network, and the driver code that is exercised is the code that ships.
//
// Settings come from the environment: TELEMT_API_PORT and TELEMT_API_TOKEN.
// Flags: -wait is how long to keep trying (default 60s), -once makes a single
// attempt. For TestLogLevel: -dcs prints the answer of GET /v1/stats/dcs,
// -handshake makes one fake-TLS handshake with a PROXY v2 header (TELEMT_LISTEN_PORT,
// TELEMT_SECRET, TELEMT_SNI, TELEMT_SRC).
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/telemt"
	"github.com/urbnywrt/postern/internal/probe"
)

func main() {
	wait := flag.Duration("wait", 60*time.Second, "how long to keep trying")
	once := flag.Bool("once", false, "make a single attempt")
	dcs := flag.Bool("dcs", false, "print the answer of GET /v1/stats/dcs and exit")
	handshake := flag.Bool("handshake", false, "make one fake-TLS handshake (TELEMT_LISTEN_PORT, TELEMT_SECRET, TELEMT_SNI, TELEMT_SRC) and exit")
	flag.Parse()

	port, err := strconv.ParseUint(os.Getenv("TELEMT_API_PORT"), 10, 16)
	if err != nil {
		fmt.Fprintln(os.Stderr, "readycheck: TELEMT_API_PORT is not a port")
		os.Exit(2)
	}
	in := engines.Instance{APIPort: uint16(port), APIToken: os.Getenv("TELEMT_API_TOKEN")}
	if *dcs {
		os.Exit(printDCs(in))
	}
	if *handshake {
		os.Exit(fakeTLS())
	}

	ctx, cancel := context.WithTimeout(context.Background(), *wait)
	defer cancel()

	d := telemt.New()
	start := time.Now()
	for {
		err := d.Ready(ctx, in)
		if err == nil {
			fmt.Printf("ready after %v\n", time.Since(start).Round(time.Millisecond))
			return
		}
		if *once || ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "not ready after %v: %v\n", time.Since(start).Round(time.Millisecond), err)
			os.Exit(1)
		}
		select {
		case <-ctx.Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// printDCs prints the body of GET /v1/stats/dcs, for the testdata of the
// diagnostics.
func printDCs(in engines.Instance) int {
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(int(in.APIPort))+"/v1/stats/dcs", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set("Authorization", in.APIToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	fmt.Printf("%s\n", body)
	return 0
}

// fakeTLS makes one fake-TLS handshake with the engine, as a client would
// through the edge: with a PROXY v2 header whose source is TELEMT_SRC.
func fakeTLS() int {
	port := os.Getenv("TELEMT_LISTEN_PORT")
	secret, err := hex.DecodeString(os.Getenv("TELEMT_SECRET"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "readycheck: TELEMT_SECRET is not hex")
		return 2
	}
	src, err := netip.ParseAddrPort(os.Getenv("TELEMT_SRC"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "readycheck: TELEMT_SRC is not an address and port")
		return 2
	}
	err = probe.FakeTLS(context.Background(), "127.0.0.1:"+port, os.Getenv("TELEMT_SNI"), secret, probe.Options{ProxyHeader: &src, Timeout: 10 * time.Second})
	if err != nil {
		fmt.Printf("handshake: %v\n", err)
		return 1
	}
	fmt.Println("handshake: ok")
	return 0
}
