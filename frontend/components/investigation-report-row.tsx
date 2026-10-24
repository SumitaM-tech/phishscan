"use client";

import { useState } from "react";
import Link from "next/link";
import { Download, ExternalLink, Loader2 } from "lucide-react";
import { investigationService } from "@/lib/investigation-service";
import { Investigation, Report } from "@/lib/types";
import { formatDate, getHostname, verdictLabel } from "@/lib/utils";

const verdictColor: Record<Investigation["risk"]["verdict"], string> = {
  malicious: "var(--danger)",
  suspicious: "var(--warning)",
  clean: "var(--success)",
  unknown: "var(--muted)",
};

export function InvestigationReportRow({
  investigation,
  existingReport,
  onReportCreated,
}: {
  investigation: Investigation;
  existingReport: Report | null;
  onReportCreated: (report: Report) => void;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const canReport = investigation.status === "complete" || investigation.status === "partial";
  const downloadUrl = existingReport ? investigationService.getReportDownloadUrl(existingReport.id) : null;

  async function handleDownload() {
    if (downloadUrl) {
      window.open(downloadUrl, "_blank", "noreferrer");
      return;
    }
    setPending(true);
    setError("");
    try {
      const report = await investigationService.createReport(investigation.id, "PDF");
      onReportCreated(report);
      const url = investigationService.getReportDownloadUrl(report.id);
      if (url) window.open(url, "_blank", "noreferrer");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Couldn't generate the PDF.");
    } finally {
      setPending(false);
    }
  }

  return (
    <article className="panel flex flex-col gap-3 p-5 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="status-dot" style={{ background: verdictColor[investigation.risk.verdict] }} />
          <p className="mono truncate text-sm font-semibold">{getHostname(investigation.target)}</p>
          <span className="rounded bg-[var(--surface-2)] px-1.5 py-0.5 text-[9px] font-bold text-[var(--muted)]">
            {verdictLabel[investigation.risk.verdict]}
          </span>
        </div>
        <p className="mono mt-1 text-[9px] text-[var(--faint)]">
          {investigation.id} · {formatDate(investigation.createdAt)} · score {investigation.risk.score}/100
        </p>
        {error && <p className="mt-1 text-[10px] text-[var(--danger)]">{error}</p>}
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Link
          href={`/investigate/${investigation.id}`}
          className="btn-secondary inline-flex h-9 items-center gap-1.5 px-3 text-[10px]"
        >
          <ExternalLink size={13} /> Open
        </Link>
        <button
          onClick={handleDownload}
          disabled={!canReport || pending}
          className="btn-primary inline-flex h-9 items-center gap-1.5 px-3 text-[10px] disabled:cursor-not-allowed disabled:opacity-50"
          title={!canReport ? "Investigation still running" : downloadUrl ? "Download PDF report" : "Generate and download PDF report"}
        >
          {pending ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
          {downloadUrl ? "Download PDF" : pending ? "Generating…" : "Generate PDF"}
        </button>
      </div>
    </article>
  );
}
