"use client";

import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { TopNav } from "@/components/top-nav";
import { CommandPalette } from "@/components/command-palette";

export function AppShell({ children }: { children: React.ReactNode }) {
  const [commandOpen, setCommandOpen] = useState(false);
  const router = useRouter();
  const pathname = usePathname();

  const onKeyDown = useCallback((event: KeyboardEvent) => {
    const target = event.target as HTMLElement;
    const isTyping = target.matches("input, textarea, select, [contenteditable='true']");
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      setCommandOpen((open) => !open);
    } else if (!isTyping && event.key.toLowerCase() === "n") {
      event.preventDefault();
      router.push("/investigate");
    } else if (!isTyping && event.key.toLowerCase() === "g" && pathname.startsWith("/investigate/")) {
      document.getElementById("infrastructure-graph")?.focus();
      document.getElementById("infrastructure-graph")?.scrollIntoView({ behavior: "smooth", block: "center" });
    } else if (event.key === "Escape") {
      setCommandOpen(false);
    }
  }, [pathname, router]);

  useEffect(() => {
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onKeyDown]);

  return (
    <>
      <TopNav onCommand={() => setCommandOpen(true)} />
      <main>{children}</main>
      <CommandPalette open={commandOpen} onClose={() => setCommandOpen(false)} />
    </>
  );
}
