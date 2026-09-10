import { useEffect, useRef, useState } from "react";
import { gradeForScore } from "../data";
import { cn } from "@/lib/utils";

/**
 * Radial posture gauge (0..100). Arc color sweeps red → amber → emerald
 * as the score climbs. `animated` lets the arc tween toward the target.
 */
export function PostureGauge({
  score,
  size = 220,
  className,
  label = "Posture Score",
}: {
  score: number;
  size?: number;
  className?: string;
  label?: string;
}) {
  const target = Math.max(0, Math.min(100, score));
  const [display, setDisplay] = useState(target);
  const raf = useRef<number | null>(null);

  useEffect(() => {
    const from = display;
    const start = performance.now();
    const dur = 900;
    const step = (now: number) => {
      const t = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(from + (target - from) * eased));
      if (t < 1) raf.current = requestAnimationFrame(step);
    };
    raf.current = requestAnimationFrame(step);
    return () => {
      if (raf.current) cancelAnimationFrame(raf.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);

  const grade = gradeForScore(display);
  const R = 88;
  const C = 2 * Math.PI * R;
  const frac = display / 100;
  const dash = C * frac;

  const stop = display >= 80 ? "#34d399" : display >= 60 ? "#a3e635" : display >= 40 ? "#facc15" : "#fb7185";
  const start = display >= 80 ? "#22d3ee" : display >= 60 ? "#34d399" : display >= 40 ? "#f59e0b" : "#f43f5e";

  return (
    <div className={cn("relative inline-flex items-center justify-center", className)} style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox="0 0 200 200" className="-rotate-90">
        <defs>
          <linearGradient id="wg-gauge-grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={start} />
            <stop offset="100%" stopColor={stop} />
          </linearGradient>
          <filter id="wg-gauge-glow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {/* track */}
        <circle cx="100" cy="100" r={R} fill="none" stroke="rgba(148,163,184,0.12)" strokeWidth="13" />
        {/* tick marks */}
        {Array.from({ length: 24 }).map((_, i) => {
          const a = (i / 24) * Math.PI * 2;
          const x1 = 100 + Math.cos(a) * (R + 9);
          const y1 = 100 + Math.sin(a) * (R + 9);
          const x2 = 100 + Math.cos(a) * (R + 13);
          const y2 = 100 + Math.sin(a) * (R + 13);
          return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke="rgba(148,163,184,0.28)" strokeWidth="1.5" />;
        })}
        {/* value arc */}
        <circle
          cx="100"
          cy="100"
          r={R}
          fill="none"
          stroke="url(#wg-gauge-grad)"
          strokeWidth="13"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${C - dash}`}
          filter="url(#wg-gauge-glow)"
          style={{ transition: "stroke-dasharray 0.15s linear" }}
        />
        {/* end cap */}
        {frac > 0.01 && (
          <circle
            cx={100 + R * Math.cos(frac * 2 * Math.PI)}
            cy={100 + R * Math.sin(frac * 2 * Math.PI)}
            r="5"
            fill={stop}
            filter="url(#wg-gauge-glow)"
          />
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">{label}</span>
        <span
          className="mt-1 font-mono text-5xl font-bold tabular-nums"
          style={{ color: stop, textShadow: `0 0 24px ${stop}55` }}
        >
          {display}
        </span>
        <span
          className="mt-1 rounded-md border px-2 py-0.5 text-sm font-bold tracking-widest"
          style={{ color: stop, borderColor: `${stop}66`, background: `${stop}14` }}
        >
          GRADE {grade.grade}
        </span>
      </div>
    </div>
  );
}
