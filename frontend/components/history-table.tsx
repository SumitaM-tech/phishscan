"use client";

import Link from "next/link";
import { ArrowUpDown, ExternalLink, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { ComparisonView } from "@/components/comparison-view";
import { Investigation } from "@/lib/types";
import { formatDate, getHostname, verdictLabel } from "@/lib/utils";

type Sort = "newest" | "oldest" | "risk-high" | "risk-low";

export function HistoryTable({ investigations }: { investigations: Investigation[] }) {
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<Sort>("newest");
  const [selected, setSelected] = useState<string[]>([]);
  const rows = useMemo(() => investigations.filter((item) => `${item.target} ${item.id} ${item.risk.verdict}`.toLowerCase().includes(query.toLowerCase())).sort((a, b) => {
    if (sort === "oldest") return +new Date(a.createdAt) - +new Date(b.createdAt);
    if (sort === "risk-high") return b.risk.score - a.risk.score;
    if (sort === "risk-low") return a.risk.score - b.risk.score;
    return +new Date(b.createdAt) - +new Date(a.createdAt);
  }), [investigations, query, sort]);
  const comparison = selected.length === 2 ? selected.map((id) => investigations.find((item) => item.id === id)!).sort((a, b) => +new Date(a.createdAt) - +new Date(b.createdAt)) : null;

  function toggle(id: string) {
    setSelected((current) => current.includes(id) ? current.filter((item) => item !== id) : current.length < 2 ? [...current, id] : [current[1], id]);
  }

  return (
    <div>
      <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative max-w-md flex-1"><Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--faint)]" size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} className="h-10 w-full rounded-md border border-[var(--line)] bg-[var(--surface)] pl-9 pr-3 text-xs outline-none focus:border-[var(--accent)]" placeholder="Search URL, ID, or verdict" aria-label="Search investigation history" /></div>
        <div className="flex items-center gap-2"><span className="hidden text-[10px] text-[var(--muted)] sm:block">Select two to compare</span><div className="relative"><ArrowUpDown className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--faint)]" size={13} /><select value={sort} onChange={(event) => setSort(event.target.value as Sort)} className="h-10 rounded-md border border-[var(--line)] bg-[var(--surface)] pl-8 pr-8 text-xs outline-none" aria-label="Sort investigations"><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="risk-high">Highest risk</option><option value="risk-low">Lowest risk</option></select></div></div>
      </div>
      <div className="panel overflow-x-auto scrollbar">
        <table className="w-full min-w-[820px] border-collapse text-left">
          <thead><tr className="border-b border-[var(--line)] text-[9px] font-bold uppercase tracking-[.13em] text-[var(--faint)]"><th className="w-12 px-4 py-3"><span className="sr-only">Compare</span></th><th className="px-4 py-3">Target</th><th className="px-4 py-3">Verdict</th><th className="px-4 py-3">Risk</th><th className="px-4 py-3">Coverage</th><th className="px-4 py-3">Observed</th><th className="px-4 py-3">Status</th><th className="w-16 px-4 py-3"><span className="sr-only">Open</span></th></tr></thead>
          <tbody>{rows.map((item) => { const active = selected.includes(item.id); return <tr key={item.id} className={`density-pad border-b border-[var(--line)] last:border-0 hover:bg-[var(--surface-2)] ${active ? "bg-[var(--accent-soft)]" : ""}`}><td className="px-4 py-4"><input type="checkbox" checked={active} onChange={() => toggle(item.id)} className="size-3.5 accent-[var(--accent)]" aria-label={`Select ${item.id} for comparison`} /></td><td className="max-w-xs px-4 py-4"><p className="mono truncate text-xs font-semibold">{getHostname(item.target)}</p><p className="mono mt-1 text-[9px] text-[var(--faint)]">{item.id}</p></td><td className="px-4 py-4"><VerdictBadge verdict={item.risk.verdict} /></td><td className="px-4 py-4"><span className="mono text-sm font-semibold">{item.risk.score}</span><span className="text-[9px] text-[var(--faint)]">/100</span></td><td className="px-4 py-4"><div className="flex items-center gap-2"><span className="h-1 w-14 overflow-hidden rounded-full bg-[var(--surface-3)]"><span className="block h-full bg-[var(--accent)]" style={{ width: `${item.coverage}%` }} /></span><span className="mono text-[9px] text-[var(--muted)]">{item.coverage}%</span></div></td><td className="whitespace-nowrap px-4 py-4 text-[10px] text-[var(--muted)]">{formatDate(item.createdAt)}</td><td className="px-4 py-4"><span className="text-[10px] capitalize text-[var(--muted)]">{item.status}</span></td><td className="px-4 py-4"><Link href={`/investigate/${item.id}`} className="grid size-8 place-items-center rounded-md border border-[var(--line)] bg-[var(--surface)] hover:border-[var(--accent)]" aria-label={`Open investigation ${item.id}`}><ExternalLink size={13} /></Link></td></tr>; })}</tbody>
        </table>
        {!rows.length && <p className="py-14 text-center text-sm text-[var(--muted)]">No investigations match your search.</p>}
      </div>
      {selected.length === 1 && <p className="mt-3 text-xs text-[var(--muted)]">Select one more investigation to compare changes.</p>}
      {comparison && <div className="mt-6"><ComparisonView left={comparison[0]} right={comparison[1]} /></div>}
    </div>
  );
}

function VerdictBadge({ verdict }: { verdict: Investigation["risk"]["verdict"] }) {
  const color = verdict === "malicious" ? "var(--danger)" : verdict === "suspicious" ? "var(--warning)" : verdict === "clean" ? "var(--success)" : "var(--muted)";
  return <span className="inline-flex items-center gap-2 text-[10px] font-bold" style={{ color }}><span className="status-dot" />{verdictLabel[verdict]}</span>;
}
