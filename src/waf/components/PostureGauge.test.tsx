import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PostureGauge } from "./PostureGauge";

/**
 * PostureGauge is the radial 0–100 score dial shown on the audit screens.
 * It tweens toward the target via requestAnimationFrame on mount — tests freeze
 * timers so the displayed value stays at the target and assertions are exact.
 */

afterEach(() => {
  vi.useRealTimers();
});

describe("PostureGauge", () => {
  it("renders the label and the raw score", () => {
    vi.useFakeTimers();
    render(<PostureGauge score={28} />);
    expect(screen.getByText("Posture Score")).toBeInTheDocument();
    expect(screen.getByText("28")).toBeInTheDocument();
  });

  it("maps a low score to a failing grade", () => {
    vi.useFakeTimers();
    render(<PostureGauge score={28} />);
    expect(screen.getByText("GRADE F")).toBeInTheDocument();
  });

  it("maps a perfect score to A+", () => {
    vi.useFakeTimers();
    render(<PostureGauge score={100} />);
    expect(screen.getByText("GRADE A+")).toBeInTheDocument();
  });

  it("maps a mid score to D and renders the arc progress", () => {
    vi.useFakeTimers();
    render(<PostureGauge score={60} />);
    expect(screen.getByText("GRADE D")).toBeInTheDocument();
    // 60% of the circumference (2π·88 ≈ 552.9) is stroked.
    const arc = document.querySelector("circle[stroke-dasharray]");
    expect(arc).not.toBeNull();
    expect(arc?.getAttribute("stroke-dasharray")).toMatch(/^33[12]\.\d+/);
  });

  it("accepts a custom label", () => {
    vi.useFakeTimers();
    render(<PostureGauge score={60} label="Baseline" />);
    expect(screen.getByText("Baseline")).toBeInTheDocument();
  });

  it("clamps out-of-range scores", () => {
    vi.useFakeTimers();
    render(<PostureGauge score={140} />);
    expect(screen.getByText("100")).toBeInTheDocument();
    render(<PostureGauge score={-10} />);
    expect(screen.getByText("0")).toBeInTheDocument();
  });
});
