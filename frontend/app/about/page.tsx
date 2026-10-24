import type { Metadata } from "next";
import { Activity, Box, Database, GitBranch, Layers, Network, ShieldCheck, Sparkles } from "lucide-react";
import { Logo } from "@/components/logo";

export const metadata: Metadata = { title: "About" };

const details = [
  ["Version", "1.0.0", Box],
  ["Build", "backend + frontend", GitBranch],
  ["Environment", "connected · local", Activity],
] as const;

const pipeline = [
  ["DNS / RDAP / TLS / HTTP / CT", "Live evidence collected per investigation from public records only."],
  ["Hand-crafted URL features", "20 host- and syntax-scoped structural signals — entropy, brand tokens, TLD, subdomain depth, malformed-query detection."],
  ["Baseline ensemble (live)", "Random Forest + XGBoost + SVM, trained on the real corpus below. Transformer + GNN fusion exists but is currently disabled — see backend README."],
  ["Threat-intel cross-check", "Every target is checked against synced PhishTank / OpenPhish records as a second, independent signal."],
] as const;

export default function AboutPage() {
  return (
    <div className="page-wrap py-12 md:py-20">
      <div className="mx-auto max-w-5xl">
        <div className="grid gap-12 lg:grid-cols-[1fr_.85fr]">
          <section>
            <Logo />
            <h1 className="mt-7 text-balance text-4xl font-semibold tracking-[-.05em] md:text-6xl">Infrastructure context for suspicious URLs.</h1>
            <p className="mt-6 text-base leading-7 text-[var(--muted)]">PhishScan investigates a URL the way an analyst would: pull the public evidence, map the infrastructure behind it, and weigh a machine-learning verdict against a live threat-intelligence check — then show the reasoning, not just a score.</p>
            <p className="mt-4 text-sm leading-6 text-[var(--muted)]">The frontend never talks to a phishing site directly. It only ever executes locally-parsed URL text and renders JSON already returned by the backend below.</p>
          </section>
          <aside className="panel p-6">
            <p className="eyebrow">Runtime</p>
            <div className="mt-5 grid gap-3">
              {details.map(([label, value, Icon]) => (
                <div key={label} className="flex items-center gap-4 rounded-lg bg-[var(--surface-2)] p-4">
                  <Icon size={17} className="text-[var(--accent)]" />
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-wider text-[var(--faint)]">{label}</p>
                    <p className="mono mt-1 text-xs">{value}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-5 rounded-lg border border-[var(--accent)]/30 bg-[var(--accent-soft)] p-4 text-xs leading-5 text-[var(--muted)]">
              <strong className="flex items-center gap-1.5 text-[var(--accent-strong)]"><Sparkles size={13} /> Live model + live feeds</strong>
              Every scan runs a Random Forest / XGBoost / SVM ensemble trained on a synthetic URL dataset, with the original real-data models kept as an automatic backup, and checks a continuously-synced PhishTank/OpenPhish record set. The Transformer + GNN hybrid path is trained but currently disabled after a joint fine-tuning run collapsed; see the backend README for the full writeup.
            </div>
          </aside>
        </div>

        <div className="mt-14">
          <p className="eyebrow">Detection pipeline</p>
          <h2 className="mt-2 text-2xl font-semibold tracking-[-.03em]">What happens when you submit a URL</h2>
          <div className="mt-6 grid gap-px overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--line)] sm:grid-cols-2">
            {pipeline.map(([title, text], i) => (
              <div key={title} className="bg-[var(--surface)] p-6">
                <span className="mono text-[10px] text-[var(--faint)]">{String(i + 1).padStart(2, "0")}</span>
                <h3 className="mt-2 text-sm font-bold">{title}</h3>
                <p className="mt-2 text-xs leading-5 text-[var(--muted)]">{text}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-10 grid gap-px overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--line)] md:grid-cols-3">
          <Principle icon={ShieldCheck} title="Safe by default" text="User input is parsed as untrusted text and never executed, rendered, or visited as a live page from the browser." />
          <Principle icon={Network} title="Relationship-first" text="Entities and their observed connections — domain, IP, ASN, registrar, certificate — stay central to every investigation view." />
          <Principle icon={Database} title="Two independent signals" text="A verified match on a known threat feed is treated as ground truth; otherwise the model's own read of the URL and its infrastructure decides." />
        </div>

        <div className="mt-10 flex items-start gap-3 rounded-xl border border-[var(--line)] bg-[var(--surface-2)] p-5 text-xs leading-5 text-[var(--muted)]">
          <Layers size={16} className="mt-0.5 shrink-0 text-[var(--faint)]" />
          <p>Trained on 443,359 real URLs after cleaning — 76,334 from a PhishTank historical bulk export and 235,795 from the PhiUSIIL Phishing URL Dataset (academic, published) — not synthetic examples. Split domain-disjoint (no site&apos;s URLs appear in both train and test) and evaluated on a held-out real hard-negative set of branded login/checkout URLs. Full methodology, feature choices, and known limitations are documented in the backend&apos;s README.</p>
        </div>
      </div>
    </div>
  );
}

function Principle({ icon: Icon, title, text }: { icon: typeof ShieldCheck; title: string; text: string }) {
  return (
    <div className="bg-[var(--surface)] p-6">
      <Icon size={19} className="text-[var(--accent)]" />
      <h2 className="mt-4 text-sm font-bold">{title}</h2>
      <p className="mt-2 text-xs leading-5 text-[var(--muted)]">{text}</p>
    </div>
  );
}
