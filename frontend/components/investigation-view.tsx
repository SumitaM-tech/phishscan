"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, ArrowLeft, Clock3, ExternalLink, FileDown, Network, RotateCw } from "lucide-react";
import { CopyButton } from "@/components/copy-button";
import { EvidenceCoverage } from "@/components/evidence-coverage";
import { FindingCard } from "@/components/finding-card";
import { InfrastructureGraph } from "@/components/infrastructure-graph";
import { RiskSummary } from "@/components/risk-summary";
import { ErrorState, LoadingState } from "@/components/states";
import { TechnicalEvidence } from "@/components/technical-evidence";
import { Timeline } from "@/components/timeline";
import { investigationService } from "@/lib/investigation-service";
import { Investigation } from "@/lib/types";
import { formatDate, getHostname } from "@/lib/utils";

export function InvestigationView({ id }: { id: string }) {
  const router = useRouter();
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [creatingReport, setCreatingReport] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const item = await investigationService.getInvestigation(id);
      if (!item) throw new Error("No investigation data is available. Connect an investigation service to load this record.");
      setInvestigation(item);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load investigation.");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    const handle = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(handle);
  }, [load]);

  const createReport = useCallback(async () => {
    if (!investigation) return;
    setCreatingReport(true);
    try {
      await investigationService.createReport(investigation.id, "PDF");
      router.push("/reports");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to create a report.");
    } finally {
      setCreatingReport(false);
    }
  }, [investigation, router]);

  if (loading) return <LoadingState full />;
  if (error || !investigation) return <div className="page-wrap py-16"><ErrorState title="Investigation unavailable" description={error || "No investigation data was found."} retry={load} /></div>;
  if (investigation.status === "running") return <div className="page-wrap py-16"><LoadingState full label={`Investigating ${getHostname(investigation.target)}…`} /></div>;

  return (
    <div className="page-wrap py-7 md:py-10">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3"><Link href="/history" className="grid size-9 place-items-center rounded-md border border-[var(--line)] bg-[var(--surface)] text-[var(--muted)] hover:text-[var(--text)]" aria-label="Back to history"><ArrowLeft size={16} /></Link><div><div className="flex items-center gap-2"><span className="mono text-[10px] text-[var(--faint)]">{investigation.id}</span><CopyButton value={investigation.id} label="Copy ID" /></div></div></div>
        <div className="flex items-center gap-2"><button onClick={load} className="btn-secondary inline-flex h-9 px-3 text-xs"><RotateCw size={14} /> Refresh</button><button onClick={createReport} disabled={creatingReport} className="btn-primary inline-flex h-9 px-3 text-xs"><FileDown size={14} /> {creatingReport ? "Creating…" : "Create report"}</button></div>
      </div>

      <header className="mb-7 border-y border-[var(--line)] py-6">
        <p className="eyebrow">Investigation target</p>
        <div className="mt-3 flex flex-wrap items-center gap-2"><h1 className="mono break-all text-xl font-semibold tracking-[-.02em] md:text-3xl">{investigation.target}</h1><CopyButton value={investigation.target} /></div>
        <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-[11px] text-[var(--muted)]"><span className="flex items-center gap-1.5"><Clock3 size={13} /> {formatDate(investigation.createdAt)}</span><span className="flex items-center gap-1.5"><Network size={13} /> {investigation.graph.nodes.length} nodes · {investigation.graph.edges.length} relationships</span><span className="flex items-center gap-1.5"><ExternalLink size={13} /> {getHostname(investigation.target)}</span></div>
      </header>

      {investigation.status === "partial" && <div className="mb-6 flex gap-3 rounded-lg border border-[var(--warning)]/35 bg-[var(--warning-soft)] p-4 text-xs text-[var(--muted)]"><AlertTriangle size={17} className="shrink-0 text-[var(--warning)]" /><p><strong className="text-[var(--text)]">Partial investigation.</strong> One or more providers were unavailable. Findings reflect only the evidence shown.</p></div>}

      <div className="grid gap-5 xl:grid-cols-[340px_1fr]">
        <div className="grid content-start gap-5"><RiskSummary risk={investigation.risk} /><EvidenceCoverage coverage={investigation.coverage} providers={investigation.providers} /></div>
        <section className="panel overflow-hidden" aria-labelledby="findings-heading"><div className="flex items-end justify-between border-b border-[var(--line)] px-5 py-4"><div><p className="eyebrow">Analysis</p><h2 id="findings-heading" className="mt-1 text-lg font-bold">Findings</h2></div><span className="mono text-[10px] text-[var(--faint)]">{investigation.findings.length} ACTIVE</span></div><div className="px-5">{investigation.findings.map((finding, index) => <FindingCard key={finding.id} finding={finding} index={index} />)}{!investigation.findings.length && <p className="py-8 text-sm text-[var(--muted)]">No findings were recorded.</p>}</div></section>
      </div>

      <section className="panel mt-5 overflow-hidden" aria-labelledby="graph-heading"><div className="flex flex-wrap items-end justify-between gap-3 border-b border-[var(--line)] p-5"><div><p className="eyebrow">Entity relationships</p><h2 id="graph-heading" className="mt-1 text-lg font-bold">Infrastructure graph</h2></div><span className="text-[10px] text-[var(--faint)]">Press <kbd className="rounded border border-[var(--line)] px-1.5 py-0.5">G</kbd> to focus</span></div><InfrastructureGraph graph={investigation.graph} /></section>

      <div className="mt-5 grid items-start gap-5 xl:grid-cols-[1fr_340px]"><TechnicalEvidence evidence={investigation.evidence} providers={investigation.providers} /><Timeline events={investigation.timeline} /></div>
    </div>
  );
}
