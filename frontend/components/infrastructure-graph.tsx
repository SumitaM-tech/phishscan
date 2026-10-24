"use client";

import { memo, useCallback, useMemo, useState } from "react";
import { Background, BackgroundVariant, Edge, Handle, MiniMap, Node, NodeProps, Position, ReactFlow, ReactFlowInstance } from "@xyflow/react";
import { Building2, CircleDot, Globe2, KeyRound, Network, ServerCog, Waypoints } from "lucide-react";
import { GraphNodePanel } from "@/components/graph-node-panel";
import { GraphToolbar } from "@/components/graph-toolbar";
import { GraphNode, InfrastructureGraph as InfrastructureGraphModel } from "@/lib/types";

type NodeData = { graphNode: GraphNode } & Record<string, unknown>;
type FlowNode = Node<NodeData, "infrastructure">;

const nodeIcons = {
  DOMAIN: Globe2,
  SUBDOMAIN: Waypoints,
  IP: CircleDot,
  ASN: Network,
  REGISTRAR: Building2,
  NAMESERVER: ServerCog,
  "TLS CERTIFICATE": KeyRound,
};

const InfrastructureNode = memo(function InfrastructureNode({ data, selected }: NodeProps<FlowNode>) {
  const item = data.graphNode;
  const Icon = nodeIcons[item.type];
  const tone = item.risk === "critical" || item.risk === "high" ? "var(--danger)" : item.risk === "medium" ? "var(--warning)" : "var(--accent)";
  return (
    <div className={`w-[220px] rounded-lg border bg-[var(--surface)] p-3 shadow-sm transition ${selected ? "border-[var(--accent)] shadow-[0_0_0_2px_var(--accent-soft)]" : "border-[var(--line-strong)]"}`}>
      <Handle type="target" position={Position.Left} className="!size-2 !border-0 !bg-[var(--line-strong)]" />
      <div className="flex items-center gap-2"><span className="grid size-7 place-items-center rounded-md" style={{ color: tone, background: `color-mix(in srgb, ${tone} 12%, transparent)` }}><Icon size={14} /></span><span className="text-[9px] font-bold tracking-[.12em] text-[var(--muted)]">{item.type}</span>{item.isTarget && <span className="ml-auto rounded bg-[var(--accent-soft)] px-1.5 py-0.5 text-[8px] font-bold text-[var(--accent)]">TARGET</span>}</div>
      <p className="mono mt-2 overflow-hidden text-ellipsis whitespace-nowrap text-[11px] font-semibold">{item.value}</p>
      <Handle type="source" position={Position.Right} className="!size-2 !border-0 !bg-[var(--line-strong)]" />
    </div>
  );
});

const nodeTypes = { infrastructure: InfrastructureNode };
const defaultEdgeOptions = { type: "smoothstep", style: { stroke: "var(--line-strong)", strokeWidth: 1.2 }, labelStyle: { fill: "var(--muted)", fontSize: 9, fontFamily: "var(--font-mono)" }, labelBgStyle: { fill: "var(--surface-2)" }, labelBgPadding: [5, 3] as [number, number], labelBgBorderRadius: 4 };

export function InfrastructureGraph({ graph }: { graph: InfrastructureGraphModel }) {
  const [instance, setInstance] = useState<ReactFlowInstance<FlowNode, Edge> | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const nodes = useMemo<FlowNode[]>(() => graph.nodes.map((item) => ({ id: item.id, type: "infrastructure", position: item.position, data: { graphNode: item }, draggable: true })), [graph.nodes]);
  const edges = useMemo<Edge[]>(() => graph.edges.map((edge) => ({ id: edge.id, source: edge.source, target: edge.target, label: edge.relationship })), [graph.edges]);
  const target = useMemo(() => graph.nodes.find((node) => node.isTarget), [graph.nodes]);
  const selected = graph.nodes.find((node) => node.id === selectedId) ?? null;

  const focusTarget = useCallback(() => {
    if (instance && target) {
      instance.setCenter(target.position.x + 110, target.position.y + 50, { zoom: 1.25, duration: 350 });
      setSelectedId(target.id);
    }
  }, [instance, target]);

  if (!graph.nodes.length) return <div className="grid h-[520px] place-items-center bg-[var(--surface-2)] text-sm text-[var(--muted)]">No infrastructure nodes were collected.</div>;

  return (
    <div id="infrastructure-graph" className="relative h-[620px] min-h-[520px] overflow-hidden bg-[var(--surface-2)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--accent)]" tabIndex={0} aria-label="Interactive infrastructure relationship graph">
      <ReactFlow<FlowNode, Edge> nodes={nodes} edges={edges} nodeTypes={nodeTypes} defaultEdgeOptions={defaultEdgeOptions} onInit={setInstance} onNodeClick={(_, node) => setSelectedId(node.id)} onPaneClick={() => setSelectedId(null)} fitView fitViewOptions={{ padding: 0.18 }} minZoom={0.35} maxZoom={2.4} nodesConnectable={false}>
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="var(--line-strong)" />
        <MiniMap nodeColor={(node) => (node.data as NodeData).graphNode.isTarget ? "var(--accent)" : "var(--line-strong)"} maskColor="color-mix(in srgb, var(--surface-2) 75%, transparent)" pannable zoomable />
      </ReactFlow>
      <GraphToolbar onZoomIn={() => instance?.zoomIn({ duration: 200 })} onZoomOut={() => instance?.zoomOut({ duration: 200 })} onFit={() => instance?.fitView({ padding: .18, duration: 350 })} onReset={() => { instance?.setViewport({ x: 0, y: 0, zoom: 1 }, { duration: 350 }); setSelectedId(null); }} onFocus={focusTarget} />
      {selected && <GraphNodePanel node={selected} edges={graph.edges} allNodes={graph.nodes} onClose={() => setSelectedId(null)} />}
      <div className="pointer-events-none absolute bottom-3 left-3 z-10 rounded-md border border-[var(--line)] bg-[var(--surface)]/90 px-3 py-2 text-[9px] text-[var(--muted)]">Scroll to zoom · drag to pan · select a node for relationships</div>
    </div>
  );
}
