import { TimelineEvent } from "@/lib/types";
import { formatDate } from "@/lib/utils";

export function Timeline({ events }: { events: TimelineEvent[] }) {
  return (
    <section className="panel p-5" aria-labelledby="timeline-heading"><div className="mb-6"><p className="eyebrow">Chronology</p><h2 id="timeline-heading" className="mt-1 text-lg font-bold">Infrastructure timeline</h2></div><ol className="relative ml-2 border-l border-[var(--line-strong)]">{events.map((event) => <li key={event.id} className="relative pb-7 pl-6 last:pb-0"><span className="absolute -left-[5px] top-1 size-2.5 rounded-full border-2 border-[var(--surface)] bg-[var(--accent)]" /><time className="mono text-[9px] text-[var(--faint)]">{formatDate(event.timestamp)}</time><h3 className="mt-1 text-xs font-bold">{event.title}</h3><p className="mt-1 text-[11px] leading-5 text-[var(--muted)]">{event.detail}</p></li>)}{!events.length && <li className="pl-6 text-xs text-[var(--muted)]">No timeline events were collected.</li>}</ol></section>
  );
}
