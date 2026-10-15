package proxies

import (
	"fmt"
	"strconv"
	"strings"

	"rsc.io/qr"
)

// The geometry of the QR codes: a quiet zone of 4 modules around the code, as
// the QR specification asks for, and 8 pixels a module at the natural size of
// the image.
const (
	qrQuietZone    = 4
	qrModulePixels = 8
)

// QRSVG returns an SVG image of the QR code of text, at error correction level
// M: black modules on a transparent background, drawn as one path with a row
// of adjacent modules as one rectangle. The same text always gives the same
// image.
func QRSVG(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("proxies: QR code: %w", err)
	}
	side := code.Size + 2*qrQuietZone
	px := strconv.Itoa(side * qrModulePixels)

	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 `)
	b.WriteString(strconv.Itoa(side) + " " + strconv.Itoa(side))
	b.WriteString(`" width="` + px + `" height="` + px + `" shape-rendering="crispEdges"><path fill="#000" d="`)
	for y := range code.Size {
		for x := 0; x < code.Size; {
			if !code.Black(x, y) {
				x++
				continue
			}
			start := x
			for x < code.Size && code.Black(x, y) {
				x++
			}
			n := strconv.Itoa(x - start)
			b.WriteString("M" + strconv.Itoa(start+qrQuietZone) + " " + strconv.Itoa(y+qrQuietZone) + "h" + n + "v1h-" + n + "z")
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
