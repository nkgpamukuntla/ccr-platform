import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, OfficeRow, post } from "../api";
import { useMe, useOrg } from "../App";

type Workspace = { id: string; name: string; kind: "courts" | "organization"; industry: string | null; offices: number; countries: string[] };
const COUNTRY: Record<string, string> = { US: "United States", AU: "Australia", SG: "Singapore", IN: "India" };

/** "Daily scan 18:00 America/New York · next 28 Oct, 03:30 your time" */
export function scanText(r: { collect_at: string; time_zone: string; next_scan: string }) {
  const next = new Date(r.next_scan);
  return `Daily scan ${r.collect_at.slice(0, 5)} ${r.time_zone.replace(/_/g, " ")} · next ${next.toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })} your time`;
}

export default function Offices() {
  const me = useMe();
  const { org, pickOrg } = useOrg();
  const [rows, setRows] = useState<OfficeRow[] | null>(null);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [types, setTypes] = useState<string[]>([]);
  const [zones, setZones] = useState<string[]>([]);
  const [form, setForm] = useState({ workspace_id: "", name: "", office_type: "", county: "", country: "", time_zone: "America/New_York", collect_at: "18:00" });
  const [error, setError] = useState("");

  const load = () => api<OfficeRow[]>("/api/offices").then(setRows).catch((e) => setError(e.message));
  useEffect(() => {
    load();
    api<string[]>("/api/time-zones").then(setZones);
    api<Workspace[]>("/api/workspaces").then((w) => {
      setWorkspaces(w);
      if (w.length) setForm((f) => ({ ...f, workspace_id: f.workspace_id || w[0].id }));
    });
  }, []);

  useEffect(() => {
    if (org) setForm((f) => ({ ...f, workspace_id: org }));
  }, [org]);

  const ws = workspaces.find((w) => w.id === form.workspace_id);
  const kind = ws?.kind ?? "courts";
  useEffect(() => {
    api<string[]>(`/api/office-types?kind=${kind}`).then((t) => {
      setTypes(t);
      setForm((f) => ({ ...f, office_type: t.includes(f.office_type) ? f.office_type : t[0] }));
    });
  }, [kind]);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await post("/api/offices", { ...form, country: form.country || null });
      setForm({ ...form, name: "", county: "" });
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const remove = async (r: OfficeRow) => {
    const typed = window.prompt(
      `Delete "${r.name}"?\n\nIt disappears from every page, its daily scans stop and its Microsoft consent is revoked. ` +
        "Its evidence and audit history are kept.\n\nType the office name to confirm:",
    );
    if (typed == null) return;
    setError("");
    try {
      await api(`/api/offices/${r.id}`, { method: "DELETE", body: JSON.stringify({ confirm_name: typed }) });
      try {
        if (localStorage.getItem("ccr.office") === r.id) localStorage.setItem("ccr.office", "");
      } catch {
        /* storage unavailable */
      }
      window.location.assign("/offices");
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const nextStep = (r: OfficeRow) => {
    for (let s = 1; s <= 6; s++) if (!r.completed_steps.includes(s)) return s;
    return 6;
  };

  const current = workspaces.find((w) => w.id === org);
  const list = (rows ?? []).filter((r) => r.workspace_id === org);

  if (!current) {
    // Step one: choose the organisation.
    return (
      <>
        <div className="page-role">Home</div>
        <h1>Organisations</h1>
        <p className="lead">Choose an organisation to see its offices. Each office is onboarded and consents on its own.</p>
        {error && <div className="error">{error}</div>}
        <div className="controls">
          {workspaces.map((w) => {
            const mine = (rows ?? []).filter((r) => r.workspace_id === w.id);
            const live = mine.filter((r) => r.live_at).length;
            return (
              <button key={w.id} className="org-card" onClick={() => pickOrg(w.id)}>
                <span className="cc">{w.kind === "courts" ? "Courts" : w.industry || "Organisation"}</span>
                <strong>{w.name}</strong>
                <span className="muted">
                  {mine.length} office{mine.length === 1 ? "" : "s"}{live ? ` · ${live} live` : ""}
                </span>
              </button>
            );
          })}
        </div>
        {workspaces.length === 0 && <p className="muted">No organisations yet. Ask a platform administrator to add yours.</p>}
        {me.is_admin && (
          <p className="muted" style={{ marginTop: "1rem" }}>
            New customer? Create the organisation under <Link to="/workspaces">Organisations</Link>, then add its offices here.
          </p>
        )}
      </>
    );
  }

  return (
    <>
      <div className="page-role">Home · {current.name}</div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h1>{current.name}</h1>
        <button className="secondary" onClick={() => pickOrg("")}>All organisations</button>
      </div>
      <p className="lead">
        {current.kind === "courts"
          ? "Consent is per governed office, so a clerk and a sheriff in one county onboard separately."
          : "Each office or unit onboards and consents on its own."}{" "}
        Choose an office to work on it; it stays selected as you move between pages.
      </p>
      {error && <div className="error">{error}</div>}
      {list.length === 0 && (
        <p className="muted">No offices yet.{me.is_admin ? " Add the first one below." : " Ask a platform administrator to add yours."}</p>
      )}
      {list.length > 0 && (
        <div style={{ marginBottom: "1.5rem" }}>
          <table>
            <thead>
              <tr>
                <th>Office</th>
                <th>{list[0].workspace_kind === "courts" ? "County" : "Location"}</th>
                <th>Profile</th>
                <th>Progress</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {list.map((r) => (
                <tr key={r.id}>
                  <td>
                    <strong>{r.name}</strong>
                    <div className="muted">{r.office_type}{r.country && <> · <span className="cc">{r.country}</span> {COUNTRY[r.country] ?? r.country}</>}</div>
                    <div className="muted" style={{ fontSize: "0.85em" }}>{scanText(r)}</div>
                  </td>
                  <td>{r.county}</td>
                  <td>{r.profile ? <span className="pill">Profile {r.profile}</span> : <span className="muted">—</span>}</td>
                  <td>{r.live_at ? <span className="pill pass">Live</span> : `${r.completed_steps.length} of 6 steps`}</td>
                  <td className="row">
                    <Link to={`/offices/${r.id}/onboarding/${nextStep(r)}`}>{r.live_at ? "Review" : "Continue"}</Link>
                    <Link to={`/offices/${r.id}/posture`}>Posture</Link>
                    <Link to={`/offices/${r.id}/findings`}>Findings</Link>
                    <Link to={`/offices/${r.id}/remediation`}>Action plan</Link>
                    <Link to={`/offices/${r.id}/evidence`}>Evidence</Link>
                    <Link to={`/offices/${r.id}/devices`}>Devices</Link>
                    <Link to={`/offices/${r.id}/members`}>Members</Link>
                    <Link to={`/offices/${r.id}/audit`}>Audit</Link>
                    {me.is_admin && (
                      <button className="secondary danger" style={{ padding: "0.15rem 0.6rem", fontSize: "0.85em" }} onClick={() => remove(r)}>
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {me.is_admin && (
        <form className="card" onSubmit={create} style={{ marginTop: "1.5rem" }}>
          <h2 style={{ marginTop: 0 }}>Add an office to {current.name}</h2>
          <label htmlFor="name">{kind === "courts" ? "Office name" : "Office or unit name"}</label>
          <input id="name" type="text" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={kind === "courts" ? "Bulloch County — Clerk of Superior Court" : "Head office IT"} />
          <label htmlFor="type">Office type</label>
          <select id="type" value={form.office_type} onChange={(e) => setForm({ ...form, office_type: e.target.value })}>
            {types.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
          {current.countries.length > 1 && (
            <>
              <label htmlFor="country">Country</label>
              <select id="country" required value={form.country} onChange={(e) => setForm({ ...form, country: e.target.value })}>
                <option value="">Choose the office's country…</option>
                {current.countries.map((c) => (
                  <option key={c} value={c}>{COUNTRY[c] ?? c}</option>
                ))}
              </select>
            </>
          )}
          {current.countries.length === 0 && (
            <p className="muted">Set this organisation's countries under <Link to={`/workspaces/${current.id}`}>Organisations</Link> so offices get the right compliance.</p>
          )}
          <label htmlFor="county">{kind === "courts" ? "County" : "City or location"}</label>
          <input id="county" type="text" required value={form.county} onChange={(e) => setForm({ ...form, county: e.target.value })} placeholder={kind === "courts" ? "Bulloch" : "Singapore"} />
          <label htmlFor="tz">Time zone and end of business day (the daily scan runs then)</label>
          <div className="row">
            <select id="tz" value={form.time_zone} onChange={(e) => setForm({ ...form, time_zone: e.target.value })} style={{ maxWidth: 280 }}>
              {zones.map((z) => (
                <option key={z} value={z}>{z.replace(/_/g, " ")}</option>
              ))}
            </select>
            <input aria-label="End of business day" type="time" value={form.collect_at} onChange={(e) => setForm({ ...form, collect_at: e.target.value })} style={{ maxWidth: 140 }} />
          </div>
          <div style={{ marginTop: "1rem" }}>
            <button type="submit">Add office</button>
          </div>
        </form>
      )}
    </>
  );
}
