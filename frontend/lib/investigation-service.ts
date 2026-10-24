import { Investigation, Report } from "@/lib/types";
import { normalizeUrl } from "@/lib/utils";

export interface InvestigationService {
  listInvestigations(): Promise<Investigation[]>;
  getInvestigation(id: string): Promise<Investigation | null>;
  createInvestigation(target: string): Promise<Investigation>;
  listReports(): Promise<Report[]>;
  createReport(investigationId: string, format: Report["format"]): Promise<Report>;
  getReportDownloadUrl(reportId: string): string | null;
}

export class UnconfiguredInvestigationService implements InvestigationService {
  async listInvestigations(): Promise<Investigation[]> {
    return [];
  }

  async getInvestigation(): Promise<Investigation | null> {
    return null;
  }

  async createInvestigation(target: string): Promise<Investigation> {
    if (!normalizeUrl(target)) throw new Error("Enter a valid HTTP or HTTPS URL.");
    throw new Error("Investigation service is not connected.");
  }

  async listReports(): Promise<Report[]> {
    return [];
  }

  async createReport(): Promise<Report> {
    throw new Error("Report service is not connected.");
  }

  getReportDownloadUrl(): string | null {
    return null;
  }
}

async function parseErrorMessage(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (typeof body?.detail === "string") return body.detail;
  } catch {
    // response wasn't JSON, fall through to generic message
  }
  return `Request failed with status ${res.status}`;
}

export class HttpInvestigationService implements InvestigationService {
  constructor(private readonly baseUrl: string) {}

  async listInvestigations(): Promise<Investigation[]> {
    const res = await fetch(`${this.baseUrl}/investigations`, { cache: "no-store" });
    if (!res.ok) throw new Error(await parseErrorMessage(res));
    return res.json();
  }

  async getInvestigation(id: string): Promise<Investigation | null> {
    const res = await fetch(`${this.baseUrl}/investigations/${id}`, { cache: "no-store" });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(await parseErrorMessage(res));
    return res.json();
  }

  async createInvestigation(target: string): Promise<Investigation> {
    if (!normalizeUrl(target)) throw new Error("Enter a valid HTTP or HTTPS URL.");
    const res = await fetch(`${this.baseUrl}/investigations`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    if (!res.ok) throw new Error(await parseErrorMessage(res));
    return res.json();
  }

  async listReports(): Promise<Report[]> {
    const res = await fetch(`${this.baseUrl}/reports`, { cache: "no-store" });
    if (!res.ok) throw new Error(await parseErrorMessage(res));
    return res.json();
  }

  async createReport(investigationId: string, format: Report["format"]): Promise<Report> {
    const res = await fetch(`${this.baseUrl}/reports`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ investigationId, format }),
    });
    if (!res.ok) throw new Error(await parseErrorMessage(res));
    return res.json();
  }

  getReportDownloadUrl(reportId: string): string | null {
    return `${this.baseUrl}/reports/${reportId}/download`;
  }
}

// Defaults to the local FastAPI backend on its default port so `npm run
// dev` + `uvicorn app.main:app` work together with zero config. Override
// with NEXT_PUBLIC_API_URL (e.g. in .env.local) for a different host,
// or set it to an empty string to fall back to UnconfiguredInvestigationService.
const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api";

export const investigationService: InvestigationService = apiUrl
  ? new HttpInvestigationService(apiUrl)
  : new UnconfiguredInvestigationService();
