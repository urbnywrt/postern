import { Box } from "@mantine/core";
import { QRCodeSVG } from "qrcode.react";

/**
 * A QR code, drawn here from `value` as inline SVG: nothing is sent anywhere, and
 * the page needs no image source. It is dark on white in both themes, with the
 * quiet zone that scanners need.
 */
export function QrCode({ value, title, size = 200 }: { value: string; title: string; size?: number }) {
  return (
    <Box bg="white" style={{ display: "inline-block", lineHeight: 0, borderRadius: "var(--mantine-radius-md)" }}>
      <QRCodeSVG
        value={value}
        title={title}
        size={size}
        level="M"
        marginSize={4}
        bgColor="#ffffff"
        fgColor="#000000"
      />
    </Box>
  );
}
