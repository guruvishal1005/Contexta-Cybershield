export interface User {
  id: string;
  email: string;
  username: string;
  fullName: string;
  role: string;
  department: string;
}

export interface Risk {
  id: string;
  name: string;
  description: string;
  severity: string;
  status: string;
  category: string;
  bwvsScore: number;
  priorityScore: number;
  cvssBase: number;
  affectedAssetsCount: number;
  cveIds: string[];
  mitigation: string;
  owner: string;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface TopRisksResponse {
  risks: Risk[];
}

export interface RiskStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  openRisks: number;
  mitigated: number;
  avgBwvs: number;
}

export interface CVE {
  id: string;
  cveId: string;
  description: string;
  cvssScore: number;
  severity: string;
  affectedSoftware: string[];
  hasExploit: boolean;
  isKev: boolean;
  cisaKev: boolean;
  publishedDate: string | null;
  lastModifiedDate: string | null;
  vectorString: string;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface TrendingCVEsResponse {
  trendingCves: CVE[];
}

export interface CVEStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  exploited: number;
  kev: number;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  incidentType: string;
  affectedAssets: string[];
  assignedTo: string;
  resolution: string;
  createdAt: string | null;
  updatedAt: string | null;
  resolvedAt: string | null;
}

export interface IncidentCreate {
  title: string;
  description?: string;
  severity?: string;
  incidentType?: string;
  affectedAssets?: string[];
  assignedTo?: string;
}

export interface IncidentUpdate {
  title?: string;
  description?: string;
  severity?: string;
  status?: string;
  incidentType?: string;
  affectedAssets?: string[];
  assignedTo?: string;
  resolution?: string;
}

export interface Asset {
  id: string;
  name: string;
  assetType: string;
  criticality: string;
  status: string;
  ipAddress: string;
  operatingSystem: string;
  owner: string;
  department: string;
  location: string;
  vulnerabilitiesCount: number;
  description: string;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface AssetCreate {
  name: string;
  assetType?: string;
  criticality?: string;
  ipAddress?: string;
  operatingSystem?: string;
  owner?: string;
  department?: string;
  location?: string;
  description?: string;
}

export interface AssetStats {
  total: number;
  byType: Record<string, number>;
  byCriticality: Record<string, number>;
  healthy: number;
  warning: number;
  critical: number;
  totalVulnerabilities: number;
}

export interface PlaybookStep {
  order: number;
  name: string;
  description: string;
  actionType: string;
  automationScript: string;
  timeoutMinutes: number;
  required: boolean;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  version: string;
  category: string;
  severityThreshold: string;
  isActive: boolean;
  steps: PlaybookStep[];
}

export interface AgentMessage {
  agent: string;
  message: string;
  timestamp: string;
}

export interface AgentAnalysisResponse {
  riskTitle: string;
  agentsUsed: string[];
  discussion: AgentMessage[];
}

export interface MLHealthSeries {
  accuracy: number[];
  f1Score: number[];
  auc: number[];
  drift: number[];
}

export interface MLHealthResponse {
  status: string;
  modelVersion: string;
  accuracy: number;
  f1Score: number;
  auc: number;
  drift: number;
  note: string;
  series: MLHealthSeries;
}

export interface TwinStats {
  totalNodes: number;
  totalEdges: number;
}

export interface SimulationResult {
  attackType: string;
  entryPoint: string;
  target: string;
  pathsFound: {
    path: string[];
    riskScore: number;
    description: string;
  }[];
  blastRadius: string[];
  riskAssessment: string;
  recommendations: string[];
}
