import { FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, post } from "../api";
import { useMe } from "../App";

type Workspace = { id: string; name: string; kind: "courts" | "organization"; industry: string | null; offices: number; can_view_all: boolean };
type Summary = {
  workspace: { id: string; name: string; kind: string; industry: string | null };
  totals: { offices: number; live: number; sites_in_register: number; sites_covered: number };
  by_profile: { profile: string; offices: number }[];
  by_type: { office_type: string; offices: number }[];
};
type Viewer = { email: string; added_at: string; added_by: string };

const KIND = { courts: "Courts", organization: "Organisation" } as const;

/** The aggregate a workspace viewer sees: counts across its offices, never another workspace. */
export function WorkspaceSummary({ id }: { id: string }) {
  const [s, setS] = useState<Summary | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    setS(null);
    api<Summary>(`/api/workspaces/${id}/summary`).then(setS).catch((e) => setError(e.message));
  }, [id]);
  if (error) return <div className="error">{error}</div>;
  if (!s) return <div className="muted">Loading…</div>;
  const courts = s.workspace.kind === "courts";
  return (
    <>
      <table>
        <tbody>
          <tr><th>Offices onboarding</th><td>{s.totals.offices}</td></tr>
          <tr><th>Live</th><td>{s.totals.live}</td></tr>
          {courts && <tr><th>Sites covered</th><td>{s.totals.sites_covered} of {s.totals.sites_in_register} in the register</td></tr>}
        </tbody>
      </table>
      <h3>Offices by type</h3>
      <table>
        <tbody>
          {s.by_type.map((t) => <tr key={t.office_type}><td>{t.office_type}</td><td>{t.offices}</td></tr>)}
          {s.by_type.length === 0 && <tr><td className="muted">No offices yet.</td></tr>}
        </tbody>
      </table>
      <h3>Offices by profile</h3>
      <table>
        <tbody>
          {s.by_profile.map((p) => (
            <tr key={p.profile}><td>{p.profile === "-" ? "Not profiled yet" : `Profile ${p.profile}`}</td><td>{p.offices}</td></tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function Viewers({ id }: { id: string }) {
  const [rows, setRows] = useState<Viewer[]>([]);
  const [email, setEmail] = useState("");
  const [msg, setMsg] = useState("");
  const load = () => api<Viewer[]>(`/api/workspaces/${id}/viewers`).then(setRows);
  useEffect(() => {
    load();
  }, [id]);
  const add = async (e: FormEvent) => {
    e.preventDefault();
    setMsg("");
    try {
      const r = await post<{ status: string }>(`/api/workspaces/${id}/viewers`, { email });
      setMsg(r.status === "invited" ? `Invitation emailed to ${email}.` : `${email} added.`);
      setEmail("");
      load();
    } catch (err) {
      setMsg((err as Error).message);
    }
  };
  const remove = async (v: string) => {
    if (!confirm(`Remove ${v} as a viewer of this workspace?`)) return;
    await api(`/api/workspaces/${id}/viewers/${encodeURIComponent(v)}`, { method: "DELETE" });
    load();
  };
  return (
    <>
      <h3>Workspace viewers (read-only, every office in this workspace)</h3>
      <table>
        <tbody>
          {rows.map((v) => (
            <tr key={v.email}><td>{v.email}</td><td className="muted">added by {v.added_by}</td><td><button className="secondary" onClick={() => remove(v.email)}>Remove</button></td></tr>
          ))}
          {rows.length === 0 && <tr><td className="muted">None yet.</td></tr>}
        </tbody>
      </table>
      <form className="row" onSubmit={add} style={{ marginTop: "0.5rem" }}>
        <input type="email" required placeholder="viewer@organisation.com" value={email} onChange={(e) => setEmail(e.target.value)} style={{ maxWidth: 320 }} />
        <button type="submit">Add viewer</button>
      </form>
      {msg && <p className="muted">{msg}</p>}
    </>
  );
}

export default function Workspaces() {
  const me = useMe();
  const { workspaceId } = useParams();
  const [rows, setRows] = useState<Workspace[]>([]);
  const [form, setForm] = useState({ name: "", kind: "organization", industry: "" });
  const [error, setError] = useState("");
  const load = () => api<Workspace[]>("/api/workspaces").then(setRows).catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, []);
  const create = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await post("/api/workspaces", { ...form, industry: form.industry || null });
      setForm({ name: "", kind: "organization", industry: "" });
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const current = rows.find((w) => w.id === workspaceId);

  return (
    <>
      <h1>Workspaces</h1>
      <p className="lead">
        One workspace per customer or programme: the Georgia courts, D-Biz itself, or any other organisation. Offices belong to one workspace, and a
        workspace viewer sees only that workspace.
      </p>
      {error && <div className="error">{error}</div>}
      <table>
        <thead><tr><th>Workspace</th><th>Kind</th><th>Industry</th><th>Offices</th></tr></thead>
        <tbody>
          {rows.map((w) => (
            <tr key={w.id}>
              <td>{w.can_view_all ? <Link to={`/workspaces/${w.id}`}>{w.name}</Link> : w.name}</td>
              <td>{KIND[w.kind]}</td>
              <td>{w.industry ?? "—"}</td>
              <td>{w.offices}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {current && (
        <div className="card" style={{ marginTop: "1.5rem" }}>
          <h2 style={{ marginTop: 0 }}>{current.name}</h2>
          <WorkspaceSummary id={current.id} />
          {me.is_admin && <Viewers id={current.id} />}
          <p><Link to="/offices">Offices in all workspaces</Link></p>
        </div>
      )}

      {me.is_admin && (
        <form className="card" onSubmit={create} style={{ marginTop: "1.5rem" }}>
          <h2 style={{ marginTop: 0 }}>Add a workspace</h2>
          <label htmlFor="wn">Name</label>
          <input id="wn" type="text" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="D-Biz Solutions" />
          <label htmlFor="wk">Kind</label>
          <select id="wk" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
            <option value="organization">Organisation (company, agency or any other customer)</option>
            <option value="courts">Courts programme (governed court offices, sites register)</option>
          </select>
          <label htmlFor="wi">Industry</label>
          <input id="wi" type="text" value={form.industry} onChange={(e) => setForm({ ...form, industry: e.target.value })} placeholder="IT services" />
          <div style={{ marginTop: "1rem" }}><button type="submit">Add workspace</button></div>
        </form>
      )}
    </>
  );
}
