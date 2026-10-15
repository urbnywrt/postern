import { describe, expect, it } from "vitest";

import { countryName } from "./countries";

describe("countryName", () => {
  it("names a country in the language of the page", () => {
    expect(countryName("DE", "en")).toBe("Germany");
    expect(countryName("DE", "ru")).toBe("Германия");
    expect(countryName("nl", "en")).toBe("Netherlands");
  });

  it("shows the code of a country that the browser does not know", () => {
    expect(countryName("QQ", "en")).toBe("QQ");
    expect(countryName("QQ", "ru")).toBe("QQ");
    expect(countryName("not a code", "en")).toBe("not a code");
  });

  it("has no name for the clients whose country is not known", () => {
    expect(countryName("", "en")).toBeNull();
  });
});
