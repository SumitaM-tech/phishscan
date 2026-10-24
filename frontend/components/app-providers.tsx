"use client";

import { SettingsProvider } from "@/components/settings-provider";
import { AppShell } from "@/components/app-shell";

export function AppProviders({ children }: { children: React.ReactNode }) {
  return (
    <SettingsProvider>
      <AppShell>{children}</AppShell>
    </SettingsProvider>
  );
}
