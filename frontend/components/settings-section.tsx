export function SettingsSection({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  return <section className="grid gap-5 border-b border-[var(--line)] py-7 last:border-0 md:grid-cols-[240px_1fr]"><div><h2 className="text-sm font-bold">{title}</h2><p className="mt-1 text-xs leading-5 text-[var(--muted)]">{description}</p></div><div className="grid gap-4">{children}</div></section>;
}
