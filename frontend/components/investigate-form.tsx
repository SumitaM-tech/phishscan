"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { UrlInput } from "@/components/url-input";
import { investigationService } from "@/lib/investigation-service";

export function InvestigateForm({ compact = false }: { compact?: boolean }) {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  async function start(url: string) {
    setLoading(true);
    try {
      const investigation = await investigationService.createInvestigation(url);
      router.push(`/investigate/${encodeURIComponent(investigation.id)}`);
    } finally {
      setLoading(false);
    }
  }
  return <UrlInput onSubmit={start} loading={loading} compact={compact} />;
}
