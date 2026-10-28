import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, OfficeRow, post } from "../api";
import { useMe } from "../App";

type Workspace = { id: string; name: string; kind: "courts" | "organization"; industry: string | null; offices: number };

/** "Daily scan 18:00 America/New York · next 28 Oct, 03:30 your time" */
export function scanText(r: { collect_at: string; time_zone: string; next_scan: string }) {
  const next = new Date(r.next_scan);
  return `Daily scan ${r.collect_at.slice(0, 5)} ${r.time_zone.replace(/_/g, " ")} · next ${next.toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })} your time`;
}

export default function Offices() {
  const me = useMe();
  const [rows, setRows] = useState<OfficeRow[] | null>(null);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [types, setTypes] = useState<string[]>([]);
  const [zones, setZones] = useState<string[]>([]);
  const [form, setForm] = useState({ workspace_id: "", name: "", office_type: "", county: "", time_zone: "America/New_York", collect_at: "18:00" });
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
      await post("/api/offices", form);
      setForm({ ...form, name: "", county: "" });
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const nextStep = (r: OfficeRow) => {
    for (let s = 1; s <= 6; s++) if (!r.completed_steps.includes(s)) return s;
    return 6;
  };

  const groups: [string, OfficeRow[]][] = [];
  for (const r of rows ?? []) {
    const g = groups.find(([name]) => name === r.workspace);
    if (g) g[1].push(r);
    else groups.push([r.workspace, [r]]);
  }

  return (
    <>
      <h1>Governed offices</h1>
      <p className="lead">
        Consent is per governed office, so a clerk and a sheriff in one county onboard separately. Offices sit in workspaces: the Georgia courts,
        or an organisation onboarded on its own.
      </p>
      {error && <div className="error">{error}</div>}
      {rows?.length === 0 && (
        <p className="muted">No offices yet.{me.is_admin ? " Add the first one below." : " Ask a platform administrator to add yours."}</p>
      )}
      {groups.map(([name, list]) => (
        <div key={name} style={{ marginBottom: "1.5rem" }}>
          <h2>{name}</h2>
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
                    <div className="muted">{r.office_type}</div>
                    <div className="muted" style={{ fontSize: "0.85em" }}>{scanText(r)}</div>
                  </td>
                  <td>{r.county}</td>
                  <td>{r.profile ? <span className="pill">Profile {r.profile}</span> : <span className="muted">—</span>}</td>
                  <td>{r.live_at ? <span className="pill pass">Live</span> : `${r.completed_steps.length} of 6 steps`}</td>
                  <td className="row">
                    <Link to={`/offices/${r.id}/onboarding/${nextStep(r)}`}>{r.live_at ? "Review" : "Continue"}</Link>
                    <Link to={`/offices/${r.id}/posture`}>Posture</Link>
                    <Link to={`/offices/${r.id}/findings`}>Findings</Link>
                    <Link to={`/offices/${r.id}/devices`}>Devices</Link>
                    <Link to={`/offices/${r.id}/members`}>Members</Link>
                    <Link to={`/offices/${r.id}/audit`}>Audit</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {me.is_admin && (
        <form className="card" onSubmit={create} style={{ marginTop: "1.5rem" }}>
          <h2 style={{ marginTop: 0 }}>Add an office</h2>
          <label htmlFor="ws">Workspace</label>
          <select id="ws" value={form.workspace_id} onChange={(e) => setForm({ ...form, workspace_id: e.target.value })}>
            {workspaces.map((w) => (
              <option key={w.id} value={w.id}>{w.name}</option>
            ))}
          </select>
          <p className="muted">New customer or industry? Create its workspace first under <Link to="/workspaces">Workspaces</Link>.</p>
          <label htmlFor="name">{kind === "courts" ? "Office name" : "Office or unit name"}</label>
          <input id="name" type="text" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={kind === "courts" ? "Bulloch County — Clerk of Superior Court" : "Head office IT"} />
          <label htmlFor="type">Office type</label>
          <select id="type" value={form.office_type} onChange={(e) => setForm({ ...form, office_type: e.target.value })}>
            {types.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
          <label htmlFor="county">{kind === "courts" ? "County" : "Location"}</label>
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
