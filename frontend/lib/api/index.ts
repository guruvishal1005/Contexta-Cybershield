export type {
  User,
  Risk,
  TopRisksResponse,
  RiskStats,
  CVE,
  TrendingCVEsResponse,
  CVEStats,
  Incident,
  IncidentCreate,
  IncidentUpdate,
  Asset,
  AssetCreate,
  AssetStats,
  Playbook,
  PlaybookStep,
  AgentMessage,
  AgentAnalysisResponse,
  MLHealthResponse,
  MLHealthSeries,
  TwinStats,
  SimulationResult,
} from "./types";

export { apiClient } from "./client";

import { apiClient } from "./client";
import type {
  User,
  Risk,
  TopRisksResponse,
  RiskStats,
  CVE,
  TrendingCVEsResponse,
  CVEStats,
  Incident,
  IncidentCreate,
  IncidentUpdate,
  Asset,
  AssetCreate,
  AssetStats,
  Playbook,
  AgentAnalysisResponse,
  MLHealthResponse,
  TwinStats,
  SimulationResult,
} from "./types";

export const authApi = {
  async login(email: string, password: string): Promise<void> {
    const data = await apiClient.postForm<{
      access_token: string;
      refresh_token?: string;
    }>("/auth/login", { username: email, password });
    apiClient.setTokens(data.access_token, data.refresh_token);
  },

  async register(data: {
    email: string;
    username: string;
    password: string;
    full_name: string;
  }): Promise<User> {
    return apiClient.post<User>("/auth/register", data);
  },

  async getMe(): Promise<User> {
    return apiClient.get<User>("/auth/me");
  },

  logout(): void {
    apiClient.clearTokens();
  },
};

export const risksApi = {
  async getTop10(): Promise<TopRisksResponse> {
    return apiClient.get<TopRisksResponse>("/risks/top10");
  },

  async list(params?: {
    page?: number;
    page_size?: number;
    status?: string;
    min_bwvs?: number;
  }): Promise<Risk[]> {
    return apiClient.get<Risk[]>("/risks", params as Record<string, unknown>);
  },

  async getById(id: string): Promise<Risk> {
    return apiClient.get<Risk>(`/risks/${id}`);
  },

  async getStats(): Promise<RiskStats> {
    return apiClient.get<RiskStats>("/risks/stats");
  },
};

export const cvesApi = {
  async list(params?: {
    page?: number;
    page_size?: number;
    severity?: string;
    min_cvss?: number;
    has_exploit?: boolean;
  }): Promise<CVE[]> {
    return apiClient.get<CVE[]>("/cves", params as Record<string, unknown>);
  },

  async getTrending(limit: number = 10): Promise<TrendingCVEsResponse> {
    return apiClient.get<TrendingCVEsResponse>("/cves/trending", { limit });
  },

  async getStats(): Promise<CVEStats> {
    return apiClient.get<CVEStats>("/cves/stats");
  },

  async getById(id: string): Promise<CVE> {
    return apiClient.get<CVE>(`/cves/${id}`);
  },

  async getPublicRecent(limit: number = 50): Promise<{ cves: CVE[] }> {
    return apiClient.get<{ cves: CVE[] }>("/cves/public/recent", { limit });
  },

  async getPublicStats(): Promise<CVEStats> {
    return apiClient.get<CVEStats>("/cves/public/stats");
  },
};

export const incidentsApi = {
  async list(params?: {
    page?: number;
    page_size?: number;
    status_filter?: string;
    severity_filter?: string;
  }): Promise<Incident[]> {
    return apiClient.get<Incident[]>(
      "/incidents",
      params as Record<string, unknown>
    );
  },

  async getById(id: string): Promise<Incident> {
    return apiClient.get<Incident>(`/incidents/${id}`);
  },

  async create(data: IncidentCreate): Promise<Incident> {
    return apiClient.post<Incident>("/incidents", data);
  },

  async update(id: string, data: IncidentUpdate): Promise<Incident> {
    return apiClient.put<Incident>(`/incidents/${id}`, data);
  },
};

export const assetsApi = {
  async list(params?: {
    page?: number;
    page_size?: number;
    asset_type?: string;
    criticality?: string;
  }): Promise<Asset[]> {
    return apiClient.get<Asset[]>("/assets", params as Record<string, unknown>);
  },

  async getById(id: string): Promise<Asset> {
    return apiClient.get<Asset>(`/assets/${id}`);
  },

  async getStats(): Promise<AssetStats> {
    return apiClient.get<AssetStats>("/assets/stats");
  },

  async create(data: AssetCreate): Promise<Asset> {
    return apiClient.post<Asset>("/assets", data);
  },
};

export const playbooksApi = {
  async list(params?: { page_size?: number }): Promise<Playbook[]> {
    return apiClient.get<Playbook[]>(
      "/playbooks",
      params as Record<string, unknown>
    );
  },
};

export const agentsApi = {
  async analyzeDemo(
    riskTitle: string,
    agents: string[] = [
      "analyst",
      "intel",
      "forensics",
      "business",
      "response",
    ]
  ): Promise<AgentAnalysisResponse> {
    return apiClient.post<AgentAnalysisResponse>(
      "/agents/analyze/demo",
      undefined,
      { risk_title: riskTitle, agents }
    );
  },
};

export const mlApi = {
  async getHealth(): Promise<MLHealthResponse> {
    return apiClient.get<MLHealthResponse>("/ml/health");
  },
};

export const twinApi = {
  async getStats(): Promise<TwinStats> {
    return apiClient.get<TwinStats>("/twin/stats");
  },

  async simulate(data: {
    attack_type: string;
    entry_point: string;
  }): Promise<SimulationResult> {
    return apiClient.post<SimulationResult>("/twin/simulate", data);
  },
};
