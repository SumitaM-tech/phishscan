"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { RotateCw, Search } from "lucide-react";
import { EmptyState, ErrorState, LoadingState } from "@/components/states";
import { InvestigationReportRow } from "@/components/investigation-report-row";
import { investigationService } from "@/lib/investigation-service";
import { Investigation, Report } from "@/lib/types";

export function ReportsView() {
  const [investigations, setInvestigations] = useState<Investigation[] | null>(null);
  const [reports, setReports] = useState<Report[]>([]);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const [invItems, reportItems] = await Promise.all([
        investigationService.listInvestigations(),
        investigationService.listReports(),
      ]);
      const sorted = [...invItems].sort((a, b) => +new Date(b.createdAt) - +new Date(a.createdAt));
      setInvestigations(sorted);
      setReports(reportItems);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to load your investigation history.");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Every URL that's ever been scanned shows up here, whether or not a
  // report has been generated for it yet -- generating one is a single
  // click away rather than a prerequisite for showing up in this list.
  const latestReportByInvestigation = useMemo(() => {
    const map = new Map<string, Report>();
    for (const report of reports) {
      const existing = map.get(report.investigationId);
      if (!existing || +new Date(report.createdAt) > +new Date(existing.createdAt)) {
        map.set(report.investigationId, report);
      }
    }
    return map;
  }, [reports]);

  const visible = useMemo(() => {
    if (!investigations) return [];
    const q = query.trim().toLowerCase();
    if (!q) return investigations;
    return investigations.filter((item) => `${item.target} ${item.id} ${item.risk.verdict}`.toLowerCase().includes(q));
  }, [investigations, query]);

  function handleReportCreated(report: Report) {
    setReports((current) => [...current.filter((r) => r.id !== report.id), report]);
  }

  return (
    <div>
      <header className="mb-8 flex flex-wrap items-end justify-between gap-5">
        <div>
          <p className="eyebrow">Export library</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-[-.04em] md:text-4xl">Reports</h1>
          <p className="mt-2 max-w-xl text-sm text-[var(--muted)]">
            Every URL you&apos;ve scanned, with a one-click PDF download for each.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="btn-secondary inline-flex h-10 px-3 text-xs"><RotateCw size={14} /> Refresh</button>
          <Link href="/investigate" className="btn-primary inline-flex h-10 px-4 text-xs"><Search size={14} /> New scan</Link>
        </div>
      </header>

      {investigations === null && !error && <LoadingState label="Loading investigation history…" />}
      {error && <ErrorState title="Reports unavailable" description={error} retry={load} />}

      {investigations !== null && !error && investigations.length === 0 && (
        <EmptyState
          title="No investigations yet"
          description="Run your first scan and it'll show up here, ready to export as a PDF."
          actionHref="/investigate"
          actionLabel="Start a scan"
        />
      )}

      {investigations !== null && investigations.length > 0 && (
        <>
          <div className="relative mb-4 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--faint)]" size={15} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="h-10 w-full rounded-md border border-[var(--line)] bg-[var(--surface)] pl-9 pr-3 text-xs outline-none focus:border-[var(--accent)]"
              placeholder="Search URL, ID, or verdict"
              aria-label="Search investigation history"
            />
          </div>
          <div className="flex flex-col gap-3">
            {visible.map((investigation) => (
              <InvestigationReportRow
                key={investigation.id}
                investigation={investigation}
                existingReport={latestReportByInvestigation.get(investigation.id) ?? null}
                onReportCreated={handleReportCreated}
              />
            ))}
            {!visible.length && <p className="py-10 text-center text-sm text-[var(--muted)]">No investigations match your search.</p>}
          </div>
        </>
      )}
    </div>
  );
}
