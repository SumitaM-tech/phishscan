"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }
  return <button onClick={copy} className="inline-flex items-center gap-1.5 rounded px-2 py-1 text-[11px] font-medium text-[var(--muted)] hover:bg-[var(--surface-2)] hover:text-[var(--text)]" aria-label={`${label}: ${value}`}>{copied ? <Check size={13} className="text-[var(--success)]" /> : <Copy size={13} />}{copied ? "Copied" : label}</button>;
}
