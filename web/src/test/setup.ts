import "@testing-library/jest-dom/vitest";

import { notifications } from "@mantine/notifications";
import { cleanup, configure } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

import i18n from "../i18n";

// findBy* and waitFor wait 5 s instead of 1: a CI runner that runs the whole
// suite at once can take more than a second for a render (the tests of
// vite.config.ts get 15 s each for that reason).
configure({ asyncUtilTimeout: 5_000 });

// jsdom has no layout engine, and Mantine reads a few browser APIs that it lacks.
// https://mantine.dev/guides/vitest/
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string): MediaQueryList => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(() => false),
  }),
});

// jsdom has no layout, so everything is 0 x 0 and a chart refuses to draw. What is
// observed is told that it is 800 x 300, once, when the observation starts.
class ResizeObserverStub {
  constructor(private readonly callback: ResizeObserverCallback) {}

  observe = (target: Element) => {
    const box = { inlineSize: 800, blockSize: 300 };
    this.callback(
      [
        {
          target,
          contentRect: new DOMRect(0, 0, 800, 300),
          borderBoxSize: [box],
          contentBoxSize: [box],
          devicePixelContentBoxSize: [box],
        },
      ],
      this,
    );
  };

  unobserve = vi.fn();
  disconnect = vi.fn();
}
Object.defineProperty(window, "ResizeObserver", { writable: true, configurable: true, value: ResizeObserverStub });
window.HTMLElement.prototype.scrollIntoView = vi.fn();

beforeEach(async () => {
  await i18n.changeLanguage("en");
});

afterEach(() => {
  cleanup();
  notifications.clean();
  vi.restoreAllMocks();
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-mantine-color-scheme");
});
