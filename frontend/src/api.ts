// Thin fetch wrapper. The session is an HttpOnly cookie, so requests only need credentials.
export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(init.headers || {}) },
    ...init,
  });
  if (res.status === 401) {
    window.location.href = "/auth/login?next=" + encodeURIComponent(window.location.pathname + window.location.search);
    throw new ApiError(401, "sign in required");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

/** Download a file the API renders (exports are audited server-side with their hash). */
export async function download(path: string): Promise<void> {
  const res = await fetch(path, { credentials: "same-origin" });
  if (res.status === 401) {
    window.location.href = "/auth/login?next=" + encodeURIComponent(window.location.pathname);
    return;
  }
  if (!res.ok) throw new ApiError(res.status, res.statusText);
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") || "")?.[1] || "export";
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const put = <T,>(path: string, body: unknown) => api<T>(path, { method: "PUT", body: JSON.stringify(body) });
export const post = <T,>(path: string, body: unknown = {}) => api<T>(path, { method: "POST", body: JSON.stringify(body) });

// ---------- types ----------
export type WorkspaceRef = { id: string; name: string; kind: "courts" | "organization" };
export type Me = {
  email: string;
  groups: string[];
  is_admin: boolean;
  is_aoc: boolean;
  viewer_workspaces: WorkspaceRef[];
  environment: string;
  microsoft_configured: boolean;
};
export type Site = { id: string; code: string; name: string; address: string | null; county: string; courts: string[] };
export type OfficeRow = {
  id: string;
  name: string;
  office_type: string;
  county: string;
  profile: string | null;
  completed_steps: number[];
  live_at: string | null;
  workspace: string;
  workspace_kind: "courts" | "organization";
  time_zone: string;
  collect_at: string;
  next_scan: string;
};
export type Office = OfficeRow & {
  signatory_name: string | null;
  technical_contact: string | null;
  sites: Site[];
  onboarding: { completed_steps: number[]; live_at: string | null } | null;
};
export type Answers = { m365: string; device_mgmt: string; edr: string; it_admin: string; api_allowed: string };
export type PathItem = { source: string; label: string; mode: "connect" | "import" | "collect" | "questionnaire" };
export type ProfileResult = { profile: string; profile_name: string; site_effort: string; path: PathItem[]; unsure: string[] };
export type Prerequisite = { group: string; item: string; who: string };
export type Connection = {
  source: string;
  mode: string;
  status: string;
  has_credential: boolean;
  consent_status: string | null;
  granted_at: string | null;
  tenant_ref: string | null;
  scopes: string[];
  consent_outdated: boolean;
};
export type Check = { check: string; result: "pass" | "warn" | "fail"; action: string };
export type ControlRow = { control: number; name: string; state: "met" | "gap" | "weak" | "not_observed" | "pending"; method: string; detail: Record<string, unknown>; as_of: string };
export type EntraSummary = {
  total: number;
  managed: number;
  compliant: number;
  activity?: { active: number; recent: number; stale: number; never: number };
  join?: Record<string, number>;
  os?: Record<string, number>;
  repeated_names?: number;
  extra_records?: number;
  company_computers_active?: number;
};
export type Posture = {
  run: { id: string; started_at: string; finished_at: string; ms_tenant_id: string; summary: Record<string, number> } | null;
  last_attempt: { started_at: string; status: string; error: string | null } | null;
  controls: ControlRow[];
  facts: {
    licences: { sku: string; enabled: number; consumed: number }[];
    devices: EntraSummary | null;
    reads: Record<string, number>;
  } | null;
};
