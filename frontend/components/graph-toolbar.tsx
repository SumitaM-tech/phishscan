import { Crosshair, LocateFixed, Maximize, RotateCcw, ZoomIn, ZoomOut } from "lucide-react";

export function GraphToolbar({ onZoomIn, onZoomOut, onFit, onReset, onFocus }: { onZoomIn: () => void; onZoomOut: () => void; onFit: () => void; onReset: () => void; onFocus: () => void }) {
  const tools = [
    { label: "Zoom in", icon: ZoomIn, action: onZoomIn },
    { label: "Zoom out", icon: ZoomOut, action: onZoomOut },
    { label: "Fit graph", icon: Maximize, action: onFit },
    { label: "Reset view", icon: RotateCcw, action: onReset },
    { label: "Focus target", icon: Crosshair, action: onFocus },
  ];
  return <div className="absolute left-3 top-3 z-10 flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--surface)] p-1 shadow-sm" aria-label="Graph controls">{tools.map(({ label, icon: Icon, action }) => <button key={label} onClick={action} className="grid size-8 place-items-center rounded-md text-[var(--muted)] hover:bg-[var(--surface-2)] hover:text-[var(--text)]" title={label} aria-label={label}><Icon size={15} /></button>)}<span className="mx-1 h-5 w-px bg-[var(--line)]" /><span className="hidden items-center gap-1.5 px-2 text-[9px] font-semibold uppercase tracking-wider text-[var(--faint)] sm:flex"><LocateFixed size={11} /> Interactive</span></div>;
}
