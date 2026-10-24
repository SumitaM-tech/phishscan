import { X } from "lucide-react";
import { CopyButton } from "@/components/copy-button";
import { GraphNode, GraphEdge } from "@/lib/types";

export function GraphNodePanel({ node, edges, allNodes, onClose }: { node: GraphNode; edges: GraphEdge[]; allNodes: GraphNode[]; onClose: () => void }) {
  const relationships = edges.filter((edge) => edge.source === node.id || edge.target === node.id);
  return (
    <aside className="absolute inset-y-3 right-3 z-20 w-[min(330px,calc(100%-24px))] overflow-y-auto rounded-xl border border-[var(--line-strong)] bg-[var(--surface)] p-4 shadow-[var(--shadow)]" aria-label="Selected graph node">
      <div className="flex items-start justify-between gap-3"><div><p className="eyebrow">{node.type}</p><h3 className="mono mt-2 break-all text-sm font-semibold">{node.value}</h3></div><button onClick={onClose} className="grid size-8 shrink-0 place-items-center rounded-md hover:bg-[var(--surface-2)]" aria-label="Close node details"><X size={16} /></button></div>
      <div className="mt-2"><CopyButton value={node.value} /></div>
      <dl className="mt-5 grid gap-3 border-t border-[var(--line)] pt-4">{Object.entries(node.metadata).map(([key, value]) => <div key={key}><dt className="text-[9px] font-bold uppercase tracking-wider text-[var(--faint)]">{key.replace(/([A-Z])/g, " $1")}</dt><dd className="mono mt-1 break-all text-xs text-[var(--muted)]">{value}</dd></div>)}</dl>
      <div className="mt-6 border-t border-[var(--line)] pt-4"><h4 className="text-xs font-bold">Relationships</h4><div className="mt-3 grid gap-2">{relationships.map((edge) => { const otherId = edge.source === node.id ? edge.target : edge.source; const other = allNodes.find((item) => item.id === otherId); return <div key={edge.id} className="rounded-md bg-[var(--surface-2)] p-3"><p className="text-[9px] font-bold uppercase text-[var(--accent)]">{edge.relationship}</p><p className="mono mt-1 break-all text-[11px]">{other?.value}</p></div>; })}{!relationships.length && <p className="text-xs text-[var(--muted)]">No relationships recorded.</p>}</div></div>
    </aside>
  );
}
