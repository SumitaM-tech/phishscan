import type { Metadata } from "next";
import { Binary, Fingerprint, Network, ScanSearch } from "lucide-react";
import { InvestigateForm } from "@/components/investigate-form";

export const metadata: Metadata = { title: "New investigation" };

const sources = [
  ["DNS", "Current record resolution", Binary],
  ["RDAP", "Domain and network registration", Fingerprint],
  ["ASN", "Route origin and ownership", Network],
  ["TLS / CT", "Certificate and issuance history", ScanSearch],
] as const;

export default function InvestigatePage() {
  return (
    <div className="page-wrap py-16 md:py-24">
      <div className="mx-auto max-w-3xl">
        <p className="eyebrow">New investigation</p>
        <h1 className="mt-3 text-balance text-4xl font-semibold tracking-[-.045em] md:text-6xl">Start with a suspicious URL.</h1>
        <p className="mt-5 max-w-2xl text-sm leading-6 text-[var(--muted)] md:text-base">Build a connected view of the target’s domain, addresses, network, registrar, nameservers, and certificates.</p>
        <div className="mt-9"><InvestigateForm /></div>
        <div className="mt-14 grid gap-px overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--line)] sm:grid-cols-2">
          {sources.map(([title, description, Icon], index) => <div key={title} className="flex items-center gap-4 bg-[var(--surface)] p-5"><span className="mono text-[9px] text-[var(--faint)]">0{index + 1}</span><Icon size={17} className="text-[var(--accent)]" /><div><p className="text-xs font-bold">{title}</p><p className="mt-1 text-[11px] text-[var(--muted)]">{description}</p></div></div>)}
        </div>
        <div className="mt-8 rounded-lg border border-[var(--line)] bg-[var(--surface-2)] p-4 text-xs leading-5 text-[var(--muted)]"><strong className="text-[var(--text)]">Passive by design:</strong> PhishScan only reads public DNS, RDAP, TLS, and certificate-transparency records for the URL you submit. It never logs in, submits forms, or executes page content.</div>
      </div>
    </div>
  );
}
