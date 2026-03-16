const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
const TOKEN_KEY =
  process.env.NEXT_PUBLIC_TOKEN_KEY || "contexta_access_token";
const REFRESH_TOKEN_KEY =
  process.env.NEXT_PUBLIC_REFRESH_TOKEN_KEY || "contexta_refresh_token";

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private getToken(): string | null {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(TOKEN_KEY);
  }

  setTokens(access: string, refresh?: string): void {
    if (typeof window === "undefined") return;
    localStorage.setItem(TOKEN_KEY, access);
    if (refresh) localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
  }

  clearTokens(): void {
    if (typeof window === "undefined") return;
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  }

  isAuthenticated(): boolean {
    return !!this.getToken();
  }

  private buildHeaders(contentType?: string): Record<string, string> {
    const headers: Record<string, string> = {};
    if (contentType) headers["Content-Type"] = contentType;
    const token = this.getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
    return headers;
  }

  private buildUrl(
    path: string,
    params?: Record<string, unknown>
  ): string {
    const url = new URL(`${this.baseUrl}${path}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) {
          if (Array.isArray(value)) {
            value.forEach((v) => url.searchParams.append(key, String(v)));
          } else {
            url.searchParams.set(key, String(value));
          }
        }
      }
    }
    return url.toString();
  }

  async get<T>(
    path: string,
    params?: Record<string, unknown>
  ): Promise<T> {
    const res = await fetch(this.buildUrl(path, params), {
      headers: this.buildHeaders(),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => res.statusText);
      throw new Error(`API error ${res.status}: ${detail}`);
    }
    return res.json();
  }

  async post<T>(
    path: string,
    body?: unknown,
    params?: Record<string, unknown>
  ): Promise<T> {
    const res = await fetch(this.buildUrl(path, params), {
      method: "POST",
      headers: this.buildHeaders("application/json"),
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => res.statusText);
      throw new Error(`API error ${res.status}: ${detail}`);
    }
    return res.json();
  }

  async postForm<T>(
    path: string,
    formData: Record<string, string>
  ): Promise<T> {
    const body = new URLSearchParams(formData);
    const res = await fetch(this.buildUrl(path), {
      method: "POST",
      headers: this.buildHeaders("application/x-www-form-urlencoded"),
      body,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => res.statusText);
      throw new Error(`API error ${res.status}: ${detail}`);
    }
    return res.json();
  }

  async put<T>(path: string, body?: unknown): Promise<T> {
    const res = await fetch(this.buildUrl(path), {
      method: "PUT",
      headers: this.buildHeaders("application/json"),
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => res.statusText);
      throw new Error(`API error ${res.status}: ${detail}`);
    }
    return res.json();
  }
}

export const apiClient = new ApiClient(API_BASE_URL);
