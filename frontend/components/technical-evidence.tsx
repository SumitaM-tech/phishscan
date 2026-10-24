"use client";

import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { CopyButton } from "@/components/copy-button";
import { Evidence, ProviderDiagnostic } from "@/lib/types";
import { ProviderStatus } from "@/components/provider-status";
import { formatDate } from "@/lib/utils";

const categories: Evidence["category"][] = ["DNS", "RDAP", "ASN", "TLS", "CT", "HTTP"];

export function TechnicalEvidence({ evidence, providers }: { evidence: Evidence[]; providers: ProviderDiagnostic[] }) {
  const [open, setOpen] = useState<string[]>(["DNS", "RDAP", "TLS"]);
  return (
    <section className="panel overflow-hidden" aria-labelledby="technical-evidence-heading">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--line)] p-5"><div><p className="eyebrow">Provider output</p><h2 id="technical-evidence-heading" className="mt-1 text-lg font-bold">Technical evidence</h2></div><span className="mono text-[10px] text-[var(--faint)]">{evidence.length} OBSERVATIONS</span></div>
      <div>
        {categories.map((category) => {
          const items = evidence.filter((item) => item.category === category);
          const provider = providers.find((item) => item.category === category);
          const expanded = open.includes(category);
          return (
            <div key={category} className="border-b border-[var(--line)] last:border-0">
              <button onClick={() => setOpen((current) => expanded ? current.filter((item) => item !== category) : [...current, category])} className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-[var(--surface-2)]" aria-expanded={expanded}><ChevronDown size={15} className={`text-[var(--muted)] transition ${expanded ? "rotate-0" : "-rotate-90"}`} /><span className="mono w-12 text-xs font-semibold">{category}</span><span className="flex-1 text-[11px] text-[var(--muted)]">{items.length ? `${items.length} observation${items.length === 1 ? "" : "s"}` : provider?.message ?? "No response"}</span>{provider && <span className={`status-dot ${provider.state === "complete" ? "text-[var(--success)]" : provider.state === "partial" ? "text-[var(--warning)]" : "text-[var(--danger)]"}`} />}</button>
              {expanded && <div className="grid gap-2 bg-[var(--surface-2)] px-5 py-4">{items.map((item) => <div key={item.id} className="grid gap-2 rounded-lg border border-[var(--line)] bg-[var(--surface)] p-3 md:grid-cols-[160px_1fr_auto] md:items-center"><div><p className="text-[10px] font-bold uppercase tracking-wider text-[var(--faint)]">{item.label}</p><p className="mono mt-1 text-[9px] text-[var(--muted)]">{item.id}</p></div><div className="min-w-0"><p className="mono break-all text-xs">{item.value}</p><p className="mt-1 text-[9px] text-[var(--faint)]">Observed {formatDate(item.observedAt)}</p></div><CopyButton value={item.value} /></div>)}{!items.length && provider && <ProviderStatus provider={provider} />}{!items.length && !provider && <p className="py-3 text-xs text-[var(--muted)]">No evidence returned for this category.</p>}</div>}
            </div>
          );
        })}
      </div>
    </section>
  );
}
