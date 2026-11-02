import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ControlRow, OfficeRow, Posture as PostureData } from "../api";
import { InfoButton, methodText, value } from "../components/Plain";
import EntraDevices from "./EntraDevices";
import Export from "./Export";

const PILL: Record<string, string> = { met: "pass", gap: "fail", weak: "warn", not_observed: "", pending: "" };
const LABEL: Record<string, string> = { met: "In place", gap: "Needs action", weak: "Partly in place", not_observed: "Not checked yet", pending: "Awaiting your answer" };
const ORDER = ["gap", "weak", "met", "not_observed", "pending"];

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
    .map(([k, v]) => `${k.replace(/_/g, " ")}: ${value(v)}`)
    .join(" · ");
}

function ControlCard({ c }: { c: ControlRow }) {
  const [open, setOpen] = useState(false);
  const { graph_reading, ...rest } = c.detail;
  return (
    <div className={`ctl ${c.state}`}>
      <h3>
        <span className="num">{c.control}</span>
        <span style={{ flex: 1 }}>{c.name}</span>
        <InfoButton on={open} toggle={() => setOpen(!open)} label="Technical detail" />
      </h3>
      <span className={`pill ${PILL[c.state]}`}>{c.label ?? LABEL[c.state]}</span>
      {c.summary && <p className="say">{c.summary}</p>}
      {c.about && <p className="muted" style={{ fontSize: "0.88em", margin: "0.25rem 0" }}>{c.about}</p>}
      <div className="muted" style={{ fontSize: "0.8em" }}>{methodText(c.method)}</div>
      {open && (
        <div className="muted" style={{ fontSize: "0.85em", marginTop: "0.5rem", borderTop: "1px dashed var(--line)", paddingTop: "0.5rem" }}>
          <div><strong>Method:</strong> {c.method}</div>
          {detailText(rest) && <div style={{ marginTop: "0.3rem" }}>{detailText(rest)}</div>}
          {graph_reading != null && (
            <div style={{ marginTop: "0.3rem" }}><strong>Direct Graph reading:</strong> {detailText(graph_reading as Record<string, unknown>)}</div>
          )}
        </div>
      )}
    </div>
  );
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

  const count = (s: string) => p.controls.filter((c) => c.state === s).length;
  const [met, gap, weak] = [count("met"), count("gap"), count("weak")];
  const open = count("not_observed") + count("pending");
  const dev = p.facts?.devices;
  const tone = gap ? "bad" : weak ? "warn" : "good";
  const parts = [gap ? `${gap} need action` : "", weak ? `${weak} partly in place` : ""].filter(Boolean).join(", ");

  return (
    <>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h1>Control posture</h1>
        <Export officeId={officeId} what="posture" />
      </div>
      <p className="lead">
        The eight controls courts ask about, in plain words. There is no overall score, and anything we could not check reads "Not checked
        yet", never "In place". <Link to={`/offices/${officeId}/remediation`}>See what to fix</Link>
      </p>
      {p.last_attempt && p.last_attempt.status === "failed" && (
        <div className="banner bad">The last scan failed on {new Date(p.last_attempt.started_at).toLocaleString()}: {p.last_attempt.error}</div>
      )}
      {!p.run ? (
        <div className="card">
          <p>No completed scan yet.</p>
          <p className="muted">Grant Microsoft 365 consent in onboarding step 4; the first scan runs at the scheduled time.</p>
        </div>
      ) : (
        <>
          <div className={`banner ${tone}`}>
            <strong>{gap + weak === 0 ? `All ${met} checked controls are in place.` : `${gap + weak} of 8 controls need attention (${parts}).`}</strong>{" "}
            {open > 0 && <span>{open} more are not checked yet or awaiting your answers.</span>}
          </div>
          <div className="stats">
            <div className="stat good"><div className="n">{met}</div><div className="l">In place</div></div>
            <div className="stat bad"><div className="n">{gap}</div><div className="l">Need action</div></div>
            <div className="stat warn"><div className="n">{weak}</div><div className="l">Partly in place</div></div>
            <div className="stat quiet"><div className="n">{open}</div><div className="l">Not checked or awaiting answer</div></div>
            {dev && (
              <div className="stat">
                <div className="n">{dev.activity?.active ?? dev.total}</div>
                <div className="l">{dev.activity ? `active devices (of ${dev.total} Entra ID records)` : "Entra ID device records"}</div>
              </div>
            )}
            <div className="stat quiet">
              <div className="n" style={{ fontSize: "1.15rem", paddingTop: "0.4rem" }}>
                {new Date(p.run.finished_at).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })}
              </div>
              <div className="l">last scan, {new Date(p.run.finished_at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}</div>
            </div>
          </div>

          <div className="controls">
            {[...p.controls]
              .sort((a, b) => ORDER.indexOf(a.state) - ORDER.indexOf(b.state) || a.control - b.control)
              .map((c) => <ControlCard key={c.control} c={c} />)}
          </div>

          {dev && <EntraDevices officeId={officeId} />}

          {p.facts && (
            <details style={{ marginTop: "1.5rem" }}>
              <summary className="muted">Technical: what Microsoft returned, and licences (tenant {p.run.ms_tenant_id})</summary>
              <h3>Reads</h3>
              <table>
                <thead><tr><th>Read</th><th>HTTP status</th></tr></thead>
                <tbody>
                  {Object.entries(p.facts.reads).map(([k, v]) => (
                    <tr key={k}><td><code>{k}</code></td><td><span className={`pill ${v === 200 ? "pass" : "warn"}`}>{v}</span></td></tr>
                  ))}
                </tbody>
              </table>
              <h3>Licences</h3>
              <table>
                <thead><tr><th>SKU</th><th>Enabled</th><th>Assigned</th></tr></thead>
                <tbody>
                  {p.facts.licences.map((l) => (
                    <tr key={l.sku}><td>{l.sku}</td><td>{l.enabled}</td><td>{l.consumed}</td></tr>
                  ))}
                </tbody>
              </table>
            </details>
          )}
        </>
      )}
    </>
  );
}
