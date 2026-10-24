import Link from "next/link";
import { SearchX } from "lucide-react";

export default function NotFound() { return <div className="page-wrap grid min-h-[70vh] place-items-center py-16 text-center"><div><SearchX className="mx-auto text-[var(--faint)]" size={34} /><p className="eyebrow mt-6">404</p><h1 className="mt-2 text-3xl font-semibold tracking-[-.04em]">Page not found</h1><p className="mt-3 text-sm text-[var(--muted)]">The requested PhishScan view does not exist.</p><Link href="/" className="btn-primary mt-6 inline-flex px-4 py-2.5 text-xs">Return home</Link></div></div>; }
