import { MutationObserver } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";

import { createQueryClient } from "./queryClient";

describe("createQueryClient", () => {
  it("never retries a call by itself: a failed call is shown, and the admin tries again", () => {
    const options = createQueryClient().getDefaultOptions();
    expect(options.queries?.retry).toBe(false);
    expect(options.mutations?.retry).toBe(false);
  });

  it("drops a mutation from the cache as soon as nothing observes it, with what it was sent", async () => {
    // A mutation is sent with a password or holds a TOTP secret. The default is to keep it
    // for five minutes after its form is gone; the cache is memory that a debugger can read.
    const client = createQueryClient();
    const observer = new MutationObserver(client, {
      mutationFn: (variables: { password: string }) => Promise.resolve(variables.password.length),
    });

    await observer.mutate({ password: "p".repeat(16) });
    // While the form is on the screen, its state (pending, error) stays available.
    expect(client.getMutationCache().getAll()).toHaveLength(1);

    observer.reset();
    await vi.waitFor(() => {
      expect(client.getMutationCache().getAll()).toHaveLength(0);
    });
  });
});
