"use client";

import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { AppSettings } from "@/lib/types";

export const defaultSettings: AppSettings = {
  theme: "dark",
  density: "comfortable",
  includeSubdomains: true,
  followRedirects: true,
  investigationTimeout: "standard",
  graphLayout: "horizontal",
  graphLabels: true,
  reportFormat: "PDF",
  reportEvidence: true,
};

interface SettingsContextValue {
  settings: AppSettings;
  updateSettings: (patch: Partial<AppSettings>) => void;
  resetSettings: () => void;
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);
  const [storageReady, setStorageReady] = useState(false);

  useEffect(() => {
    const handle = window.setTimeout(() => {
    try {
      const stored = window.localStorage.getItem("phishscan:settings");
      if (stored) setSettings({ ...defaultSettings, ...JSON.parse(stored) });
    } catch {}
    setStorageReady(true);
    }, 0);
    return () => window.clearTimeout(handle);
  }, []);

  useEffect(() => {
    if (!storageReady) return;
    const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const theme = settings.theme === "system" ? (systemDark ? "dark" : "light") : settings.theme;
    document.documentElement.dataset.theme = theme;
    document.body.classList.toggle("density-compact", settings.density === "compact");
    window.localStorage.setItem("phishscan:settings", JSON.stringify(settings));
  }, [settings, storageReady]);

  const value = useMemo(() => ({
    settings,
    updateSettings: (patch: Partial<AppSettings>) => setSettings((current) => ({ ...current, ...patch })),
    resetSettings: () => setSettings(defaultSettings),
  }), [settings]);

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings() {
  const context = useContext(SettingsContext);
  if (!context) throw new Error("useSettings must be used inside SettingsProvider");
  return context;
}
