import type { Metadata } from "next";
import { HistoryTable } from "@/components/history-table";
import { EmptyState } from "@/components/states";
import { investigationService } from "@/lib/investigation-service";

export const metadata: Metadata = { title: "History" };

export default async function HistoryPage() {
  const investigations = await investigationService.listInvestigations();
  return <div className="page-wrap py-10"><header className="mb-8 flex flex-wrap items-end justify-between gap-4"><div><p className="eyebrow">Investigation archive</p><h1 className="mt-2 text-3xl font-semibold tracking-[-.04em] md:text-4xl">History</h1><p className="mt-2 max-w-xl text-sm text-[var(--muted)]">Search completed investigations or select two records to inspect changes.</p></div><p className="mono text-[10px] text-[var(--faint)]">{investigations.length} RECORDS</p></header>{investigations.length ? <HistoryTable investigations={investigations} /> : <EmptyState title="No investigations available" description="Investigation history will appear here after a data service is connected and a URL is analyzed." actionHref="/investigate" actionLabel="Open investigation form" />}</div>;
}
