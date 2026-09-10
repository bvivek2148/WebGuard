import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// jsdom doesn't implement requestAnimationFrame; several components animate on
// mount (PostureGauge tweens its arc via rAF). Polyfill with setTimeout so they
// render in tests — under fake timers the callback simply never fires, which is
// exactly what deterministic assertions want.
if (typeof globalThis.requestAnimationFrame === "undefined") {
  globalThis.requestAnimationFrame = (cb: FrameRequestCallback) =>
    window.setTimeout(() => cb(performance.now()), 16);
}
if (typeof globalThis.cancelAnimationFrame === "undefined") {
  globalThis.cancelAnimationFrame = (id: number) => window.clearTimeout(id);
}

// Unmount every rendered tree after each test (works alongside fake timers).
afterEach(() => {
  cleanup();
});
