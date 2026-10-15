import { describe, expect, it, vi } from "vitest";

import { GEOIP_UPLOAD_URL, uploadGeoIP } from "./geoip";

function fakeFetch(status: number, body: string) {
  const spy = vi.fn<typeof fetch>(() => Promise.resolve(new Response(body, { status })));
  vi.stubGlobal("fetch", spy);
  return spy;
}

describe("uploadGeoIP", () => {
  it("sends the file as the body of a PUT, and reads the status that the panel answers", async () => {
    const spy = fakeFetch(
      200,
      JSON.stringify({ enabled: true, present: true, month: "2026-10", size: "8000000", sha256: "ab", licence: "CC BY 4.0" }),
    );
    const file = new File(["mmdb"], "dbip-country-lite-2026-10.mmdb.gz");

    const status = await uploadGeoIP(file);

    expect(spy).toHaveBeenCalledWith(GEOIP_UPLOAD_URL, expect.objectContaining({ method: "PUT", body: file }));
    expect(status.month).toBe("2026-10");
    expect(status.size).toBe(8_000_000n);
    vi.unstubAllGlobals();
  });

  it("fails with the line that the panel answered for a file it refuses", async () => {
    fakeFetch(400, "not a country database: no country.iso_code\n");

    await expect(uploadGeoIP(new File(["x"], "x.mmdb"))).rejects.toThrow("not a country database: no country.iso_code");
    vi.unstubAllGlobals();
  });

  it("fails with the status when the panel answered no text", async () => {
    fakeFetch(413, "");

    await expect(uploadGeoIP(new File(["x"], "x.mmdb"))).rejects.toThrow("HTTP 413");
    vi.unstubAllGlobals();
  });
});
