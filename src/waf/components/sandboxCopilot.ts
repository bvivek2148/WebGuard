import { ATTACK_SPECS } from "../data";
import type { AttackType, CopilotContext, SandboxResult, Severity } from "../types";

export function copilotContextFromSandbox(r: SandboxResult): CopilotContext {
  const spec = r.matchedRule ? ATTACK_SPECS.find((s) => s.ruleId === r.matchedRule) : undefined;
  const attackType: AttackType | null = spec?.type ?? (r.matchedRule ? "high-entropy" : null);
  const severity: Severity = r.matchedRule ? (spec?.severity ?? "high") : "low";
  return {
    kind: "sandbox",
    title: `${r.method} ${r.path}`,
    attackType,
    ip: "sandbox.inspect",
    country: "SG",
    severity,
    payload: "",
    ruleId: r.matchedRule,
    threatScore: r.threatScore,
    path: r.path,
  };
}
