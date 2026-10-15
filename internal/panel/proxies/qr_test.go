package proxies

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"rsc.io/qr"
)

// svgDoc is the part of the SVG of a QR code that the test reads.
type svgDoc struct {
	XMLName xml.Name `xml:"svg"`
	NS      string   `xml:"xmlns,attr"`
	ViewBox string   `xml:"viewBox,attr"`
	Width   string   `xml:"width,attr"`
	Height  string   `xml:"height,attr"`
	Rects   []struct {
		Fill string `xml:"fill,attr"`
	} `xml:"rect"`
	Paths []struct {
		Fill string `xml:"fill,attr"`
		D    string `xml:"d,attr"`
	} `xml:"path"`
}

// The geometry that the brief asks for, written out rather than taken from the
// constants of the code under test.
const (
	wantQuietZone    = 4 // modules of white around the code
	wantModulePixels = 8
)

// modules reads the black modules out of path data made of "M<x> <y>h<n>v1h-<n>z"
// runs, in the coordinates of the code (the quiet zone taken off).
func modules(t *testing.T, d string) map[[2]int]bool {
	t.Helper()
	black := map[[2]int]bool{}
	for _, run := range strings.Split(strings.TrimSuffix(d, "z"), "z") {
		var x, y, n, back int
		if _, err := fmt.Sscanf(run, "M%d %dh%dv1h-%d", &x, &y, &n, &back); err != nil {
			t.Fatalf("run %q: %v", run, err)
		}
		if n != back || n < 1 {
			t.Fatalf("run %q is not a closed row of modules", run)
		}
		for i := range n {
			black[[2]int{x - wantQuietZone + i, y - wantQuietZone}] = true
		}
	}
	return black
}

func TestQRSVG(t *testing.T) {
	const link = "tg://proxy?server=203.0.113.10&port=443&secret=ee00112233445566778899aabbccddeeff7777772e6578616d706c652e636f6d" // gitleaks:allow (a made-up test value)
	svg, err := QRSVG(link)
	if err != nil {
		t.Fatalf("QRSVG: %v", err)
	}
	var doc svgDoc
	if err := xml.Unmarshal([]byte(svg), &doc); err != nil {
		t.Fatalf("the SVG does not parse: %v\n%s", err, svg)
	}
	code, err := qr.Encode(link, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	side := code.Size + 2*wantQuietZone
	if doc.NS != "http://www.w3.org/2000/svg" {
		t.Errorf("xmlns = %q", doc.NS)
	}
	if want := fmt.Sprintf("0 0 %d %d", side, side); doc.ViewBox != want {
		t.Errorf("viewBox = %q, want %q (a quiet zone of 4 modules)", doc.ViewBox, want)
	}
	if want := strconv.Itoa(side * wantModulePixels); doc.Width != want || doc.Height != want {
		t.Errorf("size = %sx%s, want %sx%s (8 pixels a module)", doc.Width, doc.Height, want, want)
	}
	if len(doc.Rects) != 0 {
		t.Errorf("the SVG has %d rects: the background must stay transparent", len(doc.Rects))
	}
	if len(doc.Paths) != 1 || doc.Paths[0].Fill != "#000" {
		t.Fatalf("want one black path, got %+v", doc.Paths)
	}

	// The path draws exactly the black modules of the code.
	got := modules(t, doc.Paths[0].D)
	for y := range code.Size {
		for x := range code.Size {
			if got[[2]int{x, y}] != code.Black(x, y) {
				t.Fatalf("module (%d,%d): drawn %v, black %v", x, y, got[[2]int{x, y}], code.Black(x, y))
			}
			delete(got, [2]int{x, y})
		}
	}
	if len(got) != 0 {
		t.Errorf("%d modules drawn outside the code", len(got))
	}

	// The same text gives the same image.
	again, err := QRSVG(link)
	if err != nil || again != svg {
		t.Error("QRSVG is not deterministic")
	}
}

func TestQRSVGOfTextThatDoesNotFit(t *testing.T) {
	if _, err := QRSVG(strings.Repeat("x", 4000)); err == nil {
		t.Error("QRSVG of 4000 bytes: no error")
	}
}
