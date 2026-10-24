import { Binary, Braces, Network, Radar, Shield, Waypoints } from "lucide-react";
import { InvestigateForm } from "@/components/investigate-form";

const layers = [
  { icon: Binary, title: "DNS + RDAP", description: "Resolve records and inspect registration history." },
  { icon: Network, title: "ASN + routing", description: "Connect IP addresses to networks and allocations." },
  { icon: Braces, title: "TLS + CT", description: "Inspect certificates and transparency observations." },
  { icon: Waypoints, title: "Infrastructure", description: "Map relationships across domains, hosts, and providers." },
];

export default function HomePage() {
  return (
    <div className="relative overflow-hidden">
      <div className="glow-orb -left-40 -top-40 size-[520px] opacity-70" />
      <div className="glow-orb right-[-160px] top-40 size-[380px] opacity-40" />
      <div className="technical-grid pointer-events-none absolute inset-x-0 top-0 h-[720px] opacity-25" />
      <section className="page-wrap relative grid min-h-[calc(100vh-64px)] content-center py-20 lg:grid-cols-[1fr_.75fr] lg:gap-20">
        <div className="max-w-3xl">
          <p className="eyebrow mb-5 flex items-center gap-2"><Radar size={14} /> Infrastructure intelligence</p>
          <h1 className="text-balance text-[clamp(2.7rem,6vw,5.9rem)] font-semibold leading-[.94] tracking-[-.065em]">Investigate the infrastructure behind a URL.</h1>
          <p className="mt-7 max-w-2xl text-balance text-base leading-7 text-[var(--muted)] md:text-lg">PhishScan turns URL evidence into an inspectable infrastructure map—so analysts can move from a suspicious link to defensible findings.</p>
          <div className="mt-9 max-w-2xl"><InvestigateForm /></div>
          <div className="mt-7 flex flex-wrap items-center gap-x-7 gap-y-3 text-xs text-[var(--muted)]">
            <span className="flex items-center gap-2"><Shield size={14} className="text-[var(--accent)]" /> Passive investigation workflow</span>
            <span className="flex items-center gap-2"><Network size={14} className="text-[var(--accent)]" /> Relationship-first analysis</span>
          </div>
        </div>
        <div className="mt-16 self-center lg:mt-0">
          <div className="relative border-l border-[var(--line-strong)] pl-8 lg:pl-12">
            <div className="absolute -left-1 top-0 size-2 rounded-full bg-[var(--accent)]" />
            <p className="mb-8 text-xs font-semibold uppercase tracking-[.13em] text-[var(--muted)]">Evidence pipeline</p>
            <div className="grid gap-3">
              {layers.map((layer, index) => {
                const Icon = layer.icon;
                return <div key={layer.title} className="panel group flex items-center gap-4 p-4 transition hover:border-[var(--line-strong)]"><span className="mono w-5 text-[10px] text-[var(--faint)]">0{index + 1}</span><span className="grid size-10 place-items-center rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]"><Icon size={18} /></span><span><span className="block text-sm font-bold">{layer.title}</span><span className="mt-0.5 block text-xs leading-5 text-[var(--muted)]">{layer.description}</span></span></div>;
              })}
            </div>
            <p className="mt-6 text-xs leading-5 text-[var(--faint)]">Every provider above runs on submission — findings and the infrastructure graph populate live in the results view.</p>
          </div>
        </div>
      </section>
    </div>
  );
}
