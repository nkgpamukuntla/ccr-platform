import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, OfficeRow, Posture as PostureData } from "../api";

const LABEL: Record<string, string> = { met: "Met", gap: "Gap", weak: "Weak", not_observed: "Not observed", pending: "Pending" };
const PILL: Record<string, string> = { met: "pass", gap: "fail", weak: "warn", not_observed: "", pending: "" };

export function PosturePicker() {
  const [rows, setRows] = useState<OfficeRow[]>([]);
  useEffect(() => {
    api<OfficeRow[]>("/api/offices").then(setRows);
  }, []);
  return (
    <>
      <h1>Posture</h1>
      <p className="lead">Choose an office.</p>
      <table>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td><Link to={`/offices/${r.id}/posture`}>{r.name}</Link></td>
              <td>{r.county}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function detailText(d: Record<string, unknown>): string {
  return Object.entries(d)
    .filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && v.length === 0))
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${Array.isArray(v) ? v.join(", ") : String(v)}`)
    .join(" · ");
}

export default function Posture() {
  const { officeId = "" } = useParams();
  const [p, setP] = useState<PostureData | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api<PostureData>(`/api/offices/${officeId}/posture`).then(setP).catch((e) => setError(e.message));
  }, [officeId]);

  if (error) return <div className="error">{error}</div>;
  if (!p) return <div className="muted">Loading…</div>;

  const measured = p.controls.filter((c) => c.method !== "Attested" && c.state !== "not_observed").length;
  const attested = p.controls.filter((c) => c.method === "Attested").length;

  return (
    <>
      <h1>Control posture</h1>
      <p className="lead">The eight controls, each with how it was established and when. No composite score; missing evidence reads Not observed, never met.</p>
      {p.last_attempt && p.last_attempt.status === "failed" && (
        <div className="card error">Last collection failed {new Date(p.last_attempt.started_at).toLocaleString()}: {p.last_attempt.error}</div>
      )}
      {!p.run ? (
        <div className="card">
          <p>No evaluated collection yet.</p>
          <p className="muted">Grant Microsoft 365 consent in onboarding step 4; the worker collects on its schedule and the evaluator scores the result.</p>
        </div>
      ) : (
        <>
          <div className="row" style={{ marginBottom: "1rem" }}>
            <div className="card"><strong>{p.facts?.devices?.total ?? "—"}</strong><div className="muted">devices</div></div>
            <div className="card"><strong>{measured}</strong><div className="muted">measured</div></div>
            <div className="card"><strong>{attested}</strong><div className="muted">attested</div></div>
            <div className="card"><strong>{new Date(p.run.finished_at).toLocaleString()}</strong><div className="muted">as of · tenant {p.run.ms_tenant_id}</div></div>
          </div>
          <table>
            <thead><tr><th>Control</th><th>State</th><th>How established</th><th>Reading</th></tr></thead>
            <tbody>
              {p.controls.map((c) => (
                <tr key={c.control}>
                  <td>{c.control} {c.name}</td>
                  <td><span className={`pill ${PILL[c.state]}`}>{LABEL[c.state]}</span></td>
                  <td>{c.method}</td>
                  <td className="muted">{detailText(c.detail)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {p.facts && (
            <>
              <h2>What Microsoft returned</h2>
              <table>
                <thead><tr><th>Read</th><th>HTTP status</th></tr></thead>
                <tbody>
                  {Object.entries(p.facts.reads).map(([k, v]) => (
                    <tr key={k}><td><code>{k}</code></td><td><span className={`pill ${v === 200 ? "pass" : "warn"}`}>{v}</span></td></tr>
                  ))}
                </tbody>
              </table>
              <h2>Licences</h2>
              <table>
                <thead><tr><th>SKU</th><th>Enabled</th><th>Assigned</th></tr></thead>
                <tbody>
                  {p.facts.licences.map((l) => (
                    <tr key={l.sku}><td>{l.sku}</td><td>{l.enabled}</td><td>{l.consumed}</td></tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </>
      )}
    </>
  );
}
