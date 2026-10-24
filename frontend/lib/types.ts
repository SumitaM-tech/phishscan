export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ProviderState = "complete" | "partial" | "unavailable" | "pending";
export type GraphNodeType = "DOMAIN" | "SUBDOMAIN" | "IP" | "ASN" | "REGISTRAR" | "NAMESERVER" | "TLS CERTIFICATE";

export interface RiskAssessment {
  score: number;
  verdict: Verdict;
  confidence: number;
  rationale: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  summary: string;
  evidenceIds: string[];
  status: "active" | "resolved";
}

export interface Evidence {
  id: string;
  provider: string;
  category: "DNS" | "RDAP" | "ASN" | "TLS" | "CT" | "HTTP";
  label: string;
  value: string;
  observedAt: string;
  status: ProviderState;
}

export interface ProviderDiagnostic {
  id: string;
  provider: string;
  category: Evidence["category"];
  state: ProviderState;
  latencyMs?: number;
  message: string;
}

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  value: string;
  isTarget?: boolean;
  risk?: Severity;
  position: { x: number; y: number };
  metadata: Record<string, string>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
}

export interface InfrastructureGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  title: string;
  detail: string;
  type: "observed" | "registered" | "issued" | "changed";
}

export interface Investigation {
  id: string;
  target: string;
  normalizedTarget: string;
  createdAt: string;
  completedAt?: string;
  status: "queued" | "running" | "complete" | "partial" | "failed";
  risk: RiskAssessment;
  coverage: number;
  findings: Finding[];
  evidence: Evidence[];
  providers: ProviderDiagnostic[];
  graph: InfrastructureGraph;
  timeline: TimelineEvent[];
}

export interface Report {
  id: string;
  investigationId: string;
  title: string;
  format: "PDF" | "JSON" | "HTML";
  createdAt: string;
  status: "ready" | "generating";
  size: string;
}

export interface AppSettings {
  theme: "dark" | "light" | "system";
  density: "comfortable" | "compact";
  includeSubdomains: boolean;
  followRedirects: boolean;
  investigationTimeout: "standard" | "extended";
  graphLayout: "horizontal" | "radial";
  graphLabels: boolean;
  reportFormat: Report["format"];
  reportEvidence: boolean;
}
