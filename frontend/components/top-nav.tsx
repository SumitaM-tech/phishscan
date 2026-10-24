"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Command, Menu, Moon, Plus, Search, Sun, X } from "lucide-react";
import { useState } from "react";
import { Logo } from "@/components/logo";
import { useSettings } from "@/components/settings-provider";
import { cn } from "@/lib/utils";

const links = [
  { href: "/investigate", label: "Investigate" },
  { href: "/history", label: "History" },
  { href: "/reports", label: "Reports" },
  { href: "/settings", label: "Settings" },
  { href: "/about", label: "About" },
];

export function TopNav({ onCommand }: { onCommand: () => void }) {
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);
  const { settings, updateSettings } = useSettings();
  const dark = settings.theme !== "light";

  return (
    <header className="sticky top-0 z-40 border-b border-[var(--line)] bg-[color-mix(in_srgb,var(--bg)_88%,transparent)] backdrop-blur-xl">
      <div className="page-wrap flex h-16 items-center justify-between gap-5">
        <Logo />
        <nav className="hidden items-center gap-1 md:flex" aria-label="Primary navigation">
          {links.map((link) => {
            const active = pathname === link.href || (link.href === "/investigate" && pathname.startsWith("/investigate/"));
            return <Link key={link.href} href={link.href} className={cn("rounded-md px-3 py-2 text-[13px] font-medium transition-colors", active ? "bg-[var(--surface-2)] text-[var(--text)]" : "text-[var(--muted)] hover:text-[var(--text)]")}>{link.label}</Link>;
          })}
        </nav>
        <div className="flex items-center gap-2">
          <button onClick={onCommand} className="hidden h-9 items-center gap-2 rounded-md border border-[var(--line)] bg-[var(--surface)] px-3 text-xs text-[var(--muted)] transition hover:border-[var(--line-strong)] sm:flex" aria-label="Open command palette">
            <Search size={14} /><span>Search</span><span className="ml-2 flex items-center gap-0.5 rounded border border-[var(--line)] px-1.5 py-0.5 text-[10px]"><Command size={9} />K</span>
          </button>
          <button onClick={() => updateSettings({ theme: dark ? "light" : "dark" })} className="grid size-9 place-items-center rounded-md border border-[var(--line)] bg-[var(--surface)] text-[var(--muted)] hover:text-[var(--text)]" aria-label={`Switch to ${dark ? "light" : "dark"} mode`}>
            {dark ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <Link href="/investigate" className="btn-primary hidden h-9 px-3 text-xs sm:flex"><Plus size={14} /> New scan</Link>
          <button onClick={() => setMenuOpen((open) => !open)} className="grid size-9 place-items-center rounded-md border border-[var(--line)] md:hidden" aria-label="Toggle navigation" aria-expanded={menuOpen}>{menuOpen ? <X size={18} /> : <Menu size={18} />}</button>
        </div>
      </div>
      {menuOpen && (
        <nav className="page-wrap grid gap-1 border-t border-[var(--line)] py-3 md:hidden" aria-label="Mobile navigation">
          {links.map((link) => <Link onClick={() => setMenuOpen(false)} key={link.href} href={link.href} className="rounded-md px-3 py-3 text-sm text-[var(--muted)] hover:bg-[var(--surface-2)]">{link.label}</Link>)}
          <Link onClick={() => setMenuOpen(false)} href="/settings" className="rounded-md px-3 py-3 text-sm text-[var(--muted)] hover:bg-[var(--surface-2)]">Settings</Link>
        </nav>
      )}
    </header>
  );
}
