import decodeQR from "qr/decode.js";

const SCALE = 8;

/**
 * Reads a QR code that the app drew as an SVG (see QrCode) the way a phone
 * would: the modules are painted as a black and white image and given to a
 * decoder that has nothing to do with the library that drew them.
 */
export function decodeQrFromSvg(svg: Element): string {
  const side = Number(svg.getAttribute("viewBox")?.split(" ")[2]);
  // The first path is the background, the second the dark modules.
  const modules = svg.querySelectorAll("path")[1]?.getAttribute("d") ?? "";
  const pixels = side * SCALE;
  const data = new Uint8ClampedArray(pixels * pixels * 4).fill(255);
  for (const [, x, y, width] of modules.matchAll(/M(\d+)[ ,](\d+)\s*h(\d+)v1/g)) {
    for (let row = Number(y) * SCALE; row < (Number(y) + 1) * SCALE; row++) {
      for (let col = Number(x) * SCALE; col < (Number(x) + Number(width)) * SCALE; col++) {
        const at = (row * pixels + col) * 4;
        data[at] = data[at + 1] = data[at + 2] = 0;
      }
    }
  }
  return decodeQR({ width: pixels, height: pixels, data });
}
