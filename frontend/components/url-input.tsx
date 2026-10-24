"use client";

import { FormEvent, useState } from "react";
import { ArrowRight, Link2 } from "lucide-react";
import { normalizeUrl } from "@/lib/utils";

export function UrlInput({ onSubmit, initialValue = "", loading = false, compact = false }: { onSubmit: (url: string) => void | Promise<void>; initialValue?: string; loading?: boolean; compact?: boolean }) {
  const [value, setValue] = useState(initialValue);
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    const normalized = normalizeUrl(value);
    if (!normalized) {
      setError("Enter a valid HTTP or HTTPS URL, including a domain.");
      return;
    }
    setError("");
    try {
      await onSubmit(normalized);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to start the investigation.");
    }
  }

  return (
    <form onSubmit={submit} className="w-full" noValidate>
      <div className={`flex rounded-xl border bg-[var(--surface)] p-1.5 shadow-[var(--shadow)] transition focus-within:border-[var(--accent)] ${error ? "border-[var(--danger)]" : "border-[var(--line-strong)]"}`}>
        <span className="grid w-11 shrink-0 place-items-center text-[var(--muted)]"><Link2 size={18} /></span>
        <label htmlFor={compact ? "investigate-url-compact" : "investigate-url"} className="sr-only">URL to investigate</label>
        <input id={compact ? "investigate-url-compact" : "investigate-url"} value={value} onChange={(event) => setValue(event.target.value)} className={`min-w-0 flex-1 bg-transparent px-1 text-[var(--text)] outline-none placeholder:text-[var(--faint)] ${compact ? "h-10 text-sm" : "h-12 text-[15px]"}`} placeholder="https://domain.tld/path" autoComplete="url" spellCheck={false} />
        <button disabled={loading} className="btn-primary shrink-0 px-5 text-xs" type="submit">{loading ? "Preparing…" : "Investigate"}<ArrowRight size={15} /></button>
      </div>
      <div className="min-h-6 pt-2">{error ? <p className="text-xs text-[var(--danger)]" role="alert">{error}</p> : <p className="text-[11px] text-[var(--faint)]">Input is treated as untrusted and is never executed.</p>}</div>
    </form>
  );
}
