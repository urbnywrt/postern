// Command probecheck runs a probe of package probe, FakeTLS or L2, once or
// until it succeeds, or serves a plain SOCKS5 port. It exists for the
// integration test of package probe.
//
// The test probes an engine on 127.0.0.1 of the Docker daemon's host network.
// With Docker Desktop that host is a VM, out of reach of the test process, so
// the test runs this program in a container of its own on the host network,
// and the probe that runs is the code that ships. The engine's way out, which
// in production is the edge's SOCKS port, cannot be in the test process
// either: with -socks this program serves it, connecting directly to whatever
// the engine asks for, and logs every connection on stderr.
//
// Flags name the target. The secret comes in the environment, PROBE_SECRET (32
// hex digits), and is never printed. The exit status is 0 when the probe
// succeeds, 3 when the server's digest is wrong (probe.ErrBadServerDigest), 4
// when the answer to req_pq_multi is wrong (probe.ErrBadResPQ), 1 on any other
// failure and 2 on bad usage. With -socks the program serves until it is
// stopped.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/urbnywrt/postern/internal/probe"
	"github.com/urbnywrt/postern/internal/socks5"
)

func main() {
	addr := flag.String("addr", "", "address to probe, host:port")
	sni := flag.String("sni", "", "server name of the proxy")
	src := flag.String("proxy-src", "", "source address of the PROXY v2 header to send first; none when empty")
	wait := flag.Duration("wait", 0, "keep trying until the probe succeeds for this long; 0 makes a single attempt")
	l2 := flag.Bool("l2", false, "run probe.L2 to the datacenter -dc through the proxy instead of probe.FakeTLS")
	dc := flag.Int("dc", 2, "the datacenter of -l2")
	socks := flag.String("socks", "", "serve SOCKS5 on this address, connecting directly, instead of probing")
	flag.Parse()

	if *socks != "" {
		os.Exit(serveSOCKS(*socks))
	}

	secret, err := hex.DecodeString(os.Getenv("PROBE_SECRET"))
	if err != nil || len(secret) != 16 {
		fmt.Fprintln(os.Stderr, "probecheck: PROBE_SECRET must be 32 hex digits")
		os.Exit(2)
	}
	if *dc < math.MinInt16 || *dc > math.MaxInt16 {
		fmt.Fprintln(os.Stderr, "probecheck: -dc must fit in 16 bits")
		os.Exit(2)
	}
	opt := probe.Options{Timeout: 5 * time.Second}
	if *src != "" {
		ap, err := netip.ParseAddrPort(*src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "probecheck: -proxy-src: %v\n", err)
			os.Exit(2)
		}
		opt.ProxyHeader = &ap
	}
	name, run := "FakeTLS", func() error { return probe.FakeTLS(context.Background(), *addr, *sni, secret, opt) }
	if *l2 {
		name, run = fmt.Sprintf("L2 to DC%d", *dc), func() error {
			return probe.L2(context.Background(), *addr, *sni, secret, int16(*dc), opt)
		}
	}

	start := time.Now()
	for attempt := 1; ; attempt++ {
		began := time.Now()
		err := run()
		took := time.Since(start).Round(time.Millisecond)
		switch {
		case err == nil:
			fmt.Printf("%s succeeded at attempt %d, after %v (the attempt took %v)\n", name, attempt, took, time.Since(began).Round(time.Millisecond))
			return
		case errors.Is(err, probe.ErrBadServerDigest):
			fmt.Fprintf(os.Stderr, "%s, attempt %d, after %v: %v\n", name, attempt, took, err)
			os.Exit(3)
		case errors.Is(err, probe.ErrBadResPQ):
			fmt.Fprintf(os.Stderr, "%s, attempt %d, after %v: %v\n", name, attempt, took, err)
			os.Exit(4)
		case time.Since(start) >= *wait:
			fmt.Fprintf(os.Stderr, "%s, attempt %d, after %v: %v\n", name, attempt, took, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "%s, attempt %d: %v; trying again\n", name, attempt, err)
		time.Sleep(500 * time.Millisecond)
	}
}

// serveSOCKS serves SOCKS5 on addr with the package of the edge, connecting
// directly to every target, and returns the exit status when it can serve no
// more.
func serveSOCKS(addr string) int {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probecheck: %v\n", err)
		return 1
	}
	log.Info("serving SOCKS5", "addr", ln.Addr().String())
	srv := &socks5.Server{
		Logger: log,
		Dial: func(ctx context.Context, req socks5.Request) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			var d net.Dialer
			target := net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))
			conn, err := d.DialContext(ctx, "tcp", target)
			if err == nil {
				log.Debug("connected", "scope", req.Username, "target", target)
			}
			return conn, err
		},
	}
	if err := srv.Serve(ln); err != nil {
		fmt.Fprintf(os.Stderr, "probecheck: %v\n", err)
		return 1
	}
	return 0
}
