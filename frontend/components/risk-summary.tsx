import { CircleGauge, ShieldAlert } from "lucide-react";
import { RiskAssessment } from "@/lib/types";
import { verdictLabel } from "@/lib/utils";

export function RiskSummary({ risk }: { risk: RiskAssessment }) {
  const tone = risk.verdict === "malicious" ? "var(--danger)" : risk.verdict === "suspicious" ? "var(--warning)" : risk.verdict === "clean" ? "var(--success)" : "var(--muted)";
  return (
    <section className="panel density-pad p-5" aria-labelledby="risk-heading">
      <div className="flex items-start justify-between gap-4">
        <div><p className="eyebrow mb-2">Risk assessment</p><h2 id="risk-heading" className="flex items-center gap-2 text-lg font-bold"><ShieldAlert size={18} style={{ color: tone }} />{verdictLabel[risk.verdict]}</h2></div>
        <div className="text-right"><span className="mono text-3xl font-semibold" style={{ color: tone }}>{risk.score}</span><span className="text-xs text-[var(--faint)]"> / 100</span></div>
      </div>
      <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-[var(--surface-3)]"><div className="h-full rounded-full" style={{ width: `${risk.score}%`, background: tone }} /></div>
      <p className="mt-4 text-xs leading-5 text-[var(--muted)]">{risk.rationale}</p>
      <div className="mt-4 flex items-center gap-2 border-t border-[var(--line)] pt-3 text-[11px] text-[var(--muted)]"><CircleGauge size={14} /> Confidence <span className="mono font-semibold text-[var(--text)]">{risk.confidence}%</span></div>
    </section>
  );
}
