import Link from "next/link";
import { ArrowDown, ArrowRight, ArrowUp, Check, Minus, Plus } from "lucide-react";
import { Investigation } from "@/lib/types";
import { getHostname, verdictLabel } from "@/lib/utils";

export function ComparisonView({ left, right }: { left: Investigation; right: Investigation }) {
  const delta = right.risk.score - left.risk.score;
  const leftNodeValues = new Set(left.graph.nodes.map((node) => node.value));
  const rightNodeValues = new Set(right.graph.nodes.map((node) => node.value));
  const added = right.graph.nodes.filter((node) => !leftNodeValues.has(node.value));
  const removed = left.graph.nodes.filter((node) => !rightNodeValues.has(node.value));
  const evidenceDelta = right.evidence.length - left.evidence.length;
  const findingsDelta = right.findings.length - left.findings.length;
  return (
    <section className="panel overflow-hidden" aria-labelledby="comparison-heading">
      <div className="border-b border-[var(--line)] p-5"><p className="eyebrow">Side-by-side</p><h2 id="comparison-heading" className="mt-1 text-lg font-bold">Investigation comparison</h2><p className="mt-1 text-xs text-[var(--muted)]">Records compared in chronological order.</p></div>
      <div className="grid gap-px bg-[var(--line)] md:grid-cols-2"><ComparisonHeader item={left} label="Earlier" /><ComparisonHeader item={right} label="Later" /></div>
      <div className="grid gap-px border-t border-[var(--line)] bg-[var(--line)] md:grid-cols-3">
        <DeltaCell label="Risk score" value={`${delta > 0 ? "+" : ""}${delta}`} detail={`${left.risk.score} → ${right.risk.score}`} direction={delta} />
        <DeltaCell label="Findings" value={`${findingsDelta > 0 ? "+" : ""}${findingsDelta}`} detail={`${left.findings.length} → ${right.findings.length}`} direction={findingsDelta} />
        <DeltaCell label="Evidence" value={`${evidenceDelta > 0 ? "+" : ""}${evidenceDelta}`} detail={`${left.evidence.length} → ${right.evidence.length}`} direction={evidenceDelta} />
      </div>
      <div className="grid gap-6 p-5 md:grid-cols-2">
        <div><h3 className="flex items-center gap-2 text-xs font-bold"><Plus size={14} className="text-[var(--success)]" /> Added infrastructure</h3><div className="mt-3 grid gap-2">{added.map((node) => <div key={node.id} className="rounded-md bg-[var(--success-soft)] p-3"><p className="text-[9px] font-bold text-[var(--success)]">{node.type}</p><p className="mono mt-1 break-all text-[11px]">{node.value}</p></div>)}{!added.length && <p className="text-xs text-[var(--muted)]">No added infrastructure.</p>}</div></div>
        <div><h3 className="flex items-center gap-2 text-xs font-bold"><Minus size={14} className="text-[var(--danger)]" /> Removed infrastructure</h3><div className="mt-3 grid gap-2">{removed.map((node) => <div key={node.id} className="rounded-md bg-[var(--danger-soft)] p-3"><p className="text-[9px] font-bold text-[var(--danger)]">{node.type}</p><p className="mono mt-1 break-all text-[11px]">{node.value}</p></div>)}{!removed.length && <p className="text-xs text-[var(--muted)]">No removed infrastructure.</p>}</div></div>
      </div>
    </section>
  );
}

function ComparisonHeader({ item, label }: { item: Investigation; label: string }) {
  return <div className="bg-[var(--surface)] p-5"><p className="text-[9px] font-bold uppercase tracking-wider text-[var(--faint)]">{label}</p><div className="mt-2 flex items-center justify-between gap-4"><div><p className="mono text-sm font-semibold">{getHostname(item.target)}</p><p className="mt-1 text-xs text-[var(--muted)]">{verdictLabel[item.risk.verdict]}</p></div><ArrowRight size={16} className="text-[var(--faint)]" /></div><Link href={`/investigate/${item.id}`} className="mt-3 inline-flex text-[10px] font-bold text-[var(--accent)]">Open {item.id}</Link></div>;
}

function DeltaCell({ label, value, detail, direction }: { label: string; value: string; detail: string; direction: number }) {
  const Icon = direction > 0 ? ArrowUp : direction < 0 ? ArrowDown : Check;
  return <div className="bg-[var(--surface)] p-5"><p className="text-[10px] font-bold uppercase tracking-wider text-[var(--faint)]">{label}</p><div className="mt-2 flex items-end justify-between"><span className="mono text-2xl font-semibold">{value}</span><Icon size={16} className={direction > 0 ? "text-[var(--danger)]" : direction < 0 ? "text-[var(--success)]" : "text-[var(--muted)]"} /></div><p className="mono mt-1 text-[10px] text-[var(--muted)]">{detail}</p></div>;
}
