import { AlertCircle, Check, Clock3, Minus } from "lucide-react";
import { ProviderDiagnostic } from "@/lib/types";

export function ProviderStatus({ provider, compact = false }: { provider: ProviderDiagnostic; compact?: boolean }) {
  const state = {
    complete: { icon: Check, color: "var(--success)", label: "Complete" },
    partial: { icon: AlertCircle, color: "var(--warning)", label: "Partial" },
    unavailable: { icon: Minus, color: "var(--danger)", label: "Unavailable" },
    pending: { icon: Clock3, color: "var(--muted)", label: "Pending" },
  }[provider.state];
  const Icon = state.icon;
  if (compact) return <div className="flex min-w-0 items-center gap-2 text-[11px]"><Icon size={12} style={{ color: state.color }} /><span className="truncate text-[var(--muted)]">{provider.category}</span></div>;
  return <div className="flex items-center gap-3 rounded-lg border border-[var(--line)] p-3"><span className="grid size-8 place-items-center rounded-md bg-[var(--surface-2)]"><Icon size={14} style={{ color: state.color }} /></span><span className="min-w-0 flex-1"><span className="flex items-center gap-2 text-xs font-semibold">{provider.provider}<span className="font-normal text-[var(--faint)]">{provider.latencyMs ? `${provider.latencyMs} ms` : "—"}</span></span><span className="mt-0.5 block truncate text-[10px] text-[var(--muted)]">{provider.message}</span></span><span className="text-[10px] font-semibold" style={{ color: state.color }}>{state.label}</span></div>;
}
