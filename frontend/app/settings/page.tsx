import type { Metadata } from "next";
import { SettingsView } from "@/components/settings-view";

export const metadata: Metadata = { title: "Settings" };
export default function SettingsPage() { return <div className="page-wrap max-w-5xl! py-10"><header className="mb-7"><p className="eyebrow">Local preferences</p><h1 className="mt-2 text-3xl font-semibold tracking-[-.04em] md:text-4xl">Settings</h1><p className="mt-2 text-sm text-[var(--muted)]">Preferences persist in localStorage on this device.</p></header><SettingsView /></div>; }
