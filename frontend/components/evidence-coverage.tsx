import { CheckCircle2, Database } from "lucide-react";
import { ProviderDiagnostic } from "@/lib/types";
import { ProviderStatus } from "@/components/provider-status";

export function EvidenceCoverage({ coverage, providers }: { coverage: number; providers: ProviderDiagnostic[] }) {
  const complete = providers.filter((provider) => provider.state === "complete").length;
  return (
    <section className="panel density-pad p-5" aria-labelledby="coverage-heading">
      <div className="flex items-start justify-between gap-4"><div><p className="eyebrow mb-2">Evidence coverage</p><h2 id="coverage-heading" className="flex items-center gap-2 text-lg font-bold"><Database size={18} className="text-[var(--accent)]" />{coverage}% collected</h2></div><span className="mono text-xs text-[var(--muted)]">{complete}/{providers.length}</span></div>
      <div className="mt-4 grid grid-cols-6 gap-1" aria-label={`${coverage}% evidence coverage`}>{providers.map((provider) => <span key={provider.id} className="h-1.5 rounded-full" style={{ background: provider.state === "complete" ? "var(--accent)" : provider.state === "partial" ? "var(--warning)" : "var(--surface-3)" }} />)}</div>
      <div className="mt-4 grid grid-cols-2 gap-x-3 gap-y-2">{providers.map((provider) => <ProviderStatus key={provider.id} provider={provider} compact />)}</div>
      <p className="mt-4 flex items-center gap-2 border-t border-[var(--line)] pt-3 text-[11px] text-[var(--muted)]"><CheckCircle2 size={14} className="text-[var(--success)]" /> Provider collection status</p>
    </section>
  );
}
