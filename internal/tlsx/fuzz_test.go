package tlsx_test

import (
	"testing"
)

// FuzzReadClientHello feeds arbitrary bytes, under arbitrary byte budgets, to
// ReadClientHello. readChecked verifies the contract on every input: no panic,
// a non-nil result whose Raw is exactly the prefix of the input that was
// consumed, never more than maxBytes consumed, errors that fit what happened,
// and on success a result that agrees with an independent reading of Raw.
func FuzzReadClientHello(f *testing.F) {
	captured := captureClientHello(f, realConfig())
	hs := handshakeBytes(f, captured)
	small := helloRecord(helloBody(serverNameExt(hostName("www.example.com")), alpnExt("h2")))

	seeds := []struct {
		data []byte
		max  int
	}{
		{captured, defaultMax},
		{captured, len(captured)},     // the budget is exactly the hello
		{captured, len(captured) - 1}, // one byte short
		{captured, 5},
		{reframe(f, captured, 3, 200), defaultMax},
		{reframe(f, captured, 1, 1, 1), defaultMax},
		{frame(f, hs, 2), defaultMax},
		{captured[:len(captured)/2], defaultMax}, // truncated
		{small, defaultMax},
		{append(small[:len(small):len(small)], "trailing"...), defaultMax},
		{helloRecord(helloPrefix()), defaultMax}, // no extensions
		{[]byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"), defaultMax},
		{[]byte{0x16}, defaultMax},
		{[]byte{0x16, 0x03, 0x01}, defaultMax},
		{recordHeader(0x16, 0x0301, 0), defaultMax},
		{recordHeader(0x16, 0x0301, 16384+256+1), defaultMax},
		{recordHeader(0x16, 0x0200, 40), defaultMax},
		{record(0x16, 0x0301, []byte{2, 0, 0, 0}), defaultMax},
		{record(0x16, 0x0301, []byte{1, 0xff, 0xff, 0xff}), defaultMax},
		{cat(record(0x16, 0x0301, hs[:10]), record(0x15, 0x0303, hs[10:])), defaultMax},
		{[]byte{}, defaultMax},
		{small, 0},
		{small, -1},
	}
	for _, s := range seeds {
		f.Add(s.data, s.max)
	}

	f.Fuzz(func(t *testing.T, data []byte, maxBytes int) {
		_, _ = readChecked(t, data, maxBytes)
	})
}

// FuzzParseClientHelloBody feeds arbitrary bodies to ParseClientHelloBody.
// checkParseClientHelloBody verifies the contract on every input: no panic,
// ErrMalformed as the only error, nothing returned alongside an error, results
// that come from the input, and agreement with crypto/tls wherever crypto/tls
// accepts the hello.
func FuzzParseClientHelloBody(f *testing.F) {
	captured := captureClientHello(f, realConfig())
	body, ok := oracleBody(captured)
	if !ok {
		f.Fatal("cannot extract the body of the captured hello")
	}

	seeds := [][]byte{
		body,
		helloBody(serverNameExt(hostName("www.example.com")), alpnExt("h2", "http/1.1")),
		helloBody(serverNameExt(nameEntry(1, "ignored.example"), hostName("www.example.com"))),
		helloBody(serverNameExt(hostName("first.example")), serverNameExt(hostName("second.example"))),
		helloBody(extension(0x0a0a, nil), extension(0x0a0a, []byte{1})),
		helloBody(extension(0, nil), extension(16, nil)),
		helloBody(),
		helloPrefix(),
		helloPrefix()[:20],
		cat(helloPrefix(), []byte{0}),
		cat(helloBody(alpnExt("h2")), []byte{0}),
		nil,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		checkParseClientHelloBody(t, body)
	})
}
