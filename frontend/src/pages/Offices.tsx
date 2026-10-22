import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, OfficeRow, post } from "../api";
import { useMe } from "../App";

export default function Offices() {
  const me = useMe();
  const [rows, setRows] = useState<OfficeRow[] | null>(null);
  const [types, setTypes] = useState<string[]>([]);
  const [form, setForm] = useState({ name: "", office_type: "", county: "" });
  const [error, setError] = useState("");

  const load = () => api<OfficeRow[]>("/api/offices").then(setRows).catch((e) => setError(e.message));
  useEffect(() => {
    load();
    api<string[]>("/api/office-types").then((t) => {
      setTypes(t);
      setForm((f) => ({ ...f, office_type: t[0] }));
    });
  }, []);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await post("/api/offices", form);
      setForm({ name: "", office_type: types[0], county: "" });
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const nextStep = (r: OfficeRow) => {
    for (let s = 1; s <= 6; s++) if (!r.completed_steps.includes(s)) return s;
    return 6;
  };

  return (
    <>
      <h1>Governed offices</h1>
      <p className="lead">Consent is per governed office, so a clerk and a sheriff in one county onboard separately.</p>
      {error && <div className="error">{error}</div>}
      <table>
        <thead>
          <tr>
            <th>Office</th>
            <th>County</th>
            <th>Profile</th>
            <th>Progress</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows?.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                No offices yet.{me.is_admin ? " Add the first one below." : " Ask a platform administrator to add yours."}
              </td>
            </tr>
          )}
          {rows?.map((r) => (
            <tr key={r.id}>
              <td>
                <strong>{r.name}</strong>
                <div className="muted">{r.office_type}</div>
              </td>
              <td>{r.county}</td>
              <td>{r.profile ? <span className="pill">Profile {r.profile}</span> : <span className="muted">—</span>}</td>
              <td>{r.live_at ? <span className="pill pass">Live</span> : `${r.completed_steps.length} of 6 steps`}</td>
              <td className="row">
                <Link to={`/offices/${r.id}/onboarding/${nextStep(r)}`}>{r.live_at ? "Review" : "Continue"}</Link>
                <Link to={`/offices/${r.id}/posture`}>Posture</Link>
                <Link to={`/offices/${r.id}/findings`}>Findings</Link>
                <Link to={`/offices/${r.id}/members`}>Members</Link>
                <Link to={`/offices/${r.id}/audit`}>Audit</Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {me.is_admin && (
        <form className="card" onSubmit={create} style={{ marginTop: "1.5rem" }}>
          <h2 style={{ marginTop: 0 }}>Add an office</h2>
          <label htmlFor="name">Office name</label>
          <input id="name" type="text" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Bulloch County — Clerk of Superior Court" />
          <label htmlFor="type">Office type</label>
          <select id="type" value={form.office_type} onChange={(e) => setForm({ ...form, office_type: e.target.value })}>
            {types.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
          <label htmlFor="county">County</label>
          <input id="county" type="text" required value={form.county} onChange={(e) => setForm({ ...form, county: e.target.value })} placeholder="Bulloch" />
          <div style={{ marginTop: "1rem" }}>
            <button type="submit">Add office</button>
          </div>
        </form>
      )}
    </>
  );
}
