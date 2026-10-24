import Link from "next/link";
import { AlertTriangle, Inbox, LoaderCircle } from "lucide-react";

export function LoadingState({ label = "Loading investigation data…", full = false }: { label?: string; full?: boolean }) {
  return <div className={`grid place-items-center text-center ${full ? "min-h-[60vh]" : "min-h-48"}`} role="status"><div><LoaderCircle className="mx-auto mb-4 animate-spin text-[var(--accent)]" size={24} /><p className="text-sm font-medium">{label}</p></div></div>;
}

export function EmptyState({ title, description, actionHref, actionLabel }: { title: string; description: string; actionHref?: string; actionLabel?: string }) {
  return <div className="grid min-h-56 place-items-center rounded-xl border border-dashed border-[var(--line-strong)] p-8 text-center"><div><Inbox className="mx-auto mb-4 text-[var(--faint)]" size={26} /><h3 className="font-semibold">{title}</h3><p className="mx-auto mt-2 max-w-md text-sm text-[var(--muted)]">{description}</p>{actionHref && actionLabel && <Link href={actionHref} className="btn-primary mt-5 inline-flex px-4 py-2 text-xs">{actionLabel}</Link>}</div></div>;
}

export function ErrorState({ title = "Something went wrong", description, retry }: { title?: string; description: string; retry?: () => void }) {
  return <div className="grid min-h-56 place-items-center rounded-xl border border-[var(--danger)]/30 bg-[var(--danger-soft)] p-8 text-center" role="alert"><div><AlertTriangle className="mx-auto mb-4 text-[var(--danger)]" size={26} /><h3 className="font-semibold">{title}</h3><p className="mx-auto mt-2 max-w-md text-sm text-[var(--muted)]">{description}</p>{retry && <button onClick={retry} className="btn-secondary mt-5 px-4 py-2 text-xs">Try again</button>}</div></div>;
}
