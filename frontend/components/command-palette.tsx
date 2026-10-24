"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { FileText, History, Info, Search, Settings, ShieldCheck } from "lucide-react";

const commands = [
  { label: "New investigation", description: "Analyze a URL", href: "/investigate", icon: ShieldCheck, hint: "N" },
  { label: "Investigation history", description: "Search previous scans", href: "/history", icon: History },
  { label: "Reports", description: "Review generated reports", href: "/reports", icon: FileText },
  { label: "Settings", description: "Theme, graph and report defaults", href: "/settings", icon: Settings },
  { label: "About PhishScan", description: "Build and environment details", href: "/about", icon: Info },
];

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const filtered = commands.filter((command) => `${command.label} ${command.description}`.toLowerCase().includes(query.toLowerCase()));

  useEffect(() => {
    if (open) {
      window.setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  if (!open) return null;

  function select(href: string) {
    router.push(href);
    onClose();
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center bg-black/55 px-4 pt-[12vh] backdrop-blur-sm" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className="panel-raised w-full max-w-xl overflow-hidden" role="dialog" aria-modal="true" aria-label="Command palette">
        <div className="flex items-center gap-3 border-b border-[var(--line)] px-4">
          <Search size={18} className="text-[var(--muted)]" />
          <input ref={inputRef} value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && filtered[0]) select(filtered[0].href); }} className="h-14 flex-1 bg-transparent text-sm outline-none placeholder:text-[var(--faint)]" placeholder="Search pages and actions…" aria-label="Search commands" />
          <kbd className="rounded border border-[var(--line)] px-2 py-1 text-[10px] text-[var(--muted)]">ESC</kbd>
        </div>
        <div className="max-h-[370px] overflow-y-auto p-2">
          <p className="px-2 pb-2 pt-1 text-[10px] font-bold uppercase tracking-[.15em] text-[var(--faint)]">Navigate</p>
          {filtered.map((command) => {
            const Icon = command.icon;
            return (
              <button key={command.href} onClick={() => select(command.href)} className="flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left hover:bg-[var(--surface-2)]">
                <span className="grid size-9 place-items-center rounded-md border border-[var(--line)] bg-[var(--surface)] text-[var(--accent)]"><Icon size={17} /></span>
                <span className="min-w-0 flex-1"><span className="block text-sm font-semibold">{command.label}</span><span className="block truncate text-xs text-[var(--muted)]">{command.description}</span></span>
                {command.hint && <kbd className="rounded border border-[var(--line)] px-2 py-1 text-[10px] text-[var(--muted)]">{command.hint}</kbd>}
              </button>
            );
          })}
          {!filtered.length && <p className="px-3 py-10 text-center text-sm text-[var(--muted)]">No matching commands</p>}
        </div>
      </div>
    </div>
  );
}
