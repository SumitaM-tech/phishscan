import type { Metadata } from "next";
import { InvestigationView } from "@/components/investigation-view";

export const metadata: Metadata = { title: "Investigation" };

export default async function InvestigationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <InvestigationView id={decodeURIComponent(id)} />;
}
