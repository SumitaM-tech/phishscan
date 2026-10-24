import Link from "next/link";

export function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <Link href="/" className="group flex items-center gap-2.5" aria-label="PhishScan home">
      <span className="relative grid size-8 place-items-center rounded-[9px] border border-[var(--line-strong)]" style={{ background: "var(--accent-gradient)" }}>
        <span className="size-3.5 rotate-45 border-2 border-white/85" />
        <span className="absolute size-1.5 rounded-full bg-white" />
      </span>
      {!compact && <span className="text-[15px] font-bold tracking-[-0.03em]">Phish<span className="text-[var(--accent)]">Scan</span></span>}
    </Link>
  );
}
