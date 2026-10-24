import { FileCode2, FileJson2, FileText, Loader2 } from "lucide-react";
import { Report } from "@/lib/types";
import { formatDate } from "@/lib/utils";

export function ReportCard({ report, downloadUrl }: { report: Report; downloadUrl: string | null }) {
  const Icon = report.format === "JSON" ? FileJson2 : report.format === "HTML" ? FileCode2 : FileText;
  const ready = report.status === "ready" && downloadUrl;
  return (
    <article className="panel group flex flex-col p-5 transition hover:border-[var(--line-strong)]">
      <div className="flex items-start justify-between">
        <span className="grid size-10 place-items-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]"><Icon size={19} /></span>
        <span className="rounded bg-[var(--surface-2)] px-2 py-1 text-[9px] font-bold text-[var(--muted)]">{report.format}</span>
      </div>
      <h2 className="mt-5 text-sm font-bold leading-5">{report.title}</h2>
      <p className="mono mt-2 text-[9px] text-[var(--faint)]">{report.id} · {report.size}</p>
      <div className="mt-auto flex items-center justify-between border-t border-[var(--line)] pt-4">
        <time className="text-[10px] text-[var(--muted)]">{formatDate(report.createdAt)}</time>
        {ready ? (
          <a href={downloadUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[10px] font-bold text-[var(--accent)] hover:text-[var(--accent-strong)]">Open</a>
        ) : (
          <span className="inline-flex items-center gap-1.5 text-[10px] font-bold text-[var(--faint)]"><Loader2 size={12} className="animate-spin" /> Generating</span>
        )}
      </div>
    </article>
  );
}
