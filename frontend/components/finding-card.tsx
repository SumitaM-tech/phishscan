import { ChevronRight } from "lucide-react";
import { Finding } from "@/lib/types";

export function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const colors = { critical: "var(--danger)", high: "var(--danger)", medium: "var(--warning)", low: "var(--accent)", info: "var(--muted)" };
  return (
    <article className="group grid grid-cols-[38px_1fr_auto] items-start gap-3 border-b border-[var(--line)] py-4 last:border-0">
      <span className="mono pt-0.5 text-[10px] text-[var(--faint)]">F-{String(index + 1).padStart(2, "0")}</span>
      <div><div className="mb-1.5 flex flex-wrap items-center gap-2"><h3 className="text-sm font-bold">{finding.title}</h3><span className="rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider" style={{ color: colors[finding.severity], background: `color-mix(in srgb, ${colors[finding.severity]} 13%, transparent)` }}>{finding.severity}</span></div><p className="text-xs leading-5 text-[var(--muted)]">{finding.summary}</p><p className="mono mt-2 text-[9px] text-[var(--faint)]">{finding.evidenceIds.join(" · ")}</p></div>
      <ChevronRight size={16} className="mt-1 text-[var(--faint)] transition group-hover:translate-x-0.5 group-hover:text-[var(--text)]" />
    </article>
  );
}
