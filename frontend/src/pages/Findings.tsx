import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, OfficeRow } from "../api";
import { InfoButton } from "../components/Plain";

type Row = {
  product: string;
  policy_id: string;
  requirement: string;
  criticality: string;
  status: "pass" | "fail" | "warning" | "na" | "error";
  details: string;
  source: "collected" | "imported";
  baseline: string;
  assessed_at: string;
  imported_by: string | null;
  plain: { title: string; why: string; fix: string } | null;
};
type Data = { summary: Record<string, Record<string, number>>; results: Row[] };

const LABEL: Record<Row["status"], string> = { pass: "OK", fail: "Must fix", warning: "Recommended", na: "Not applicable", error: "Could not check" };
const PILL: Record<Row["status"], string> = { pass: "pass", fail: "fail", warning: "warn", na: "", error: "warn" };
const PRODUCT: Record<string, string> = {
  AAD: "Entra ID", DEFENDER: "Defender", EXO: "Exchange Online", POWERPLATFORM: "Power Platform",
  SHAREPOINT: "SharePoint", TEAMS: "Teams", POWERBI: "Power BI",
};

export function FindingsPicker() {
  const [rows, setRows] = useState<OfficeRow[]>([]);
  useEffect(() => {
    api<OfficeRow[]>("/api/offices").then(setRows);
  }, []);
  return (
    <>
      <h1>Findings</h1>
      <p className="lead">Choose an office.</p>
      <table>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}><td><Link to={`/offices/${r.id}/findings`}>{r.name}</Link></td><td>{r.county}</td></tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function PolicyCard({ r }: { r: Row }) {
  const [open, setOpen] = useState(false);
  const sev = r.status === "fail" ? "Mandatory" : r.status === "warning" ? "High" : "";
  return (
    <div className={`finding ${sev}`} style={r.status === "pass" ? { borderLeftColor: "var(--good)" } : undefined}>
      <div className="head">
        <span className={`pill ${PILL[r.status]}`}>{LABEL[r.status]}</span>
        <div className="t">
          {r.plain?.title ?? r.requirement}
          {r.plain && r.status !== "pass" && (
            <div className="do muted" style={{ fontWeight: 400 }}><strong style={{ color: "var(--ink)" }}>What to do:</strong> {r.plain.fix}</div>
          )}
        </div>
        <InfoButton on={open} toggle={() => setOpen(!open)} />
      </div>
      {open && (
        <dl className="more">
          {r.plain && (<><dt>Why it matters</dt><dd>{r.plain.why}</dd></>)}
          <dt>What Microsoft 365 shows</dt>
          <dd>{r.details || "—"}</dd>
          <dt>How we know</dt>
          <dd>
            {r.source === "collected" ? "Read from Microsoft 365" : "From an uploaded ScubaGear report"}, checked with CISA ScubaGear {r.baseline} rules ·{" "}
            {new Date(r.assessed_at).toLocaleString()}{r.imported_by ? ` · by ${r.imported_by}` : ""}
          </dd>
          <dt>Technical reference (for IT)</dt>
          <dd className="muted">{r.policy_id} ({r.criticality}): {r.requirement}</dd>
        </dl>
      )}
    </div>
  );
}

export default function Findings() {
  const { officeId = "" } = useParams();
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState("");
  const [product, setProduct] = useState("all");
  const [status, setStatus] = useState("not-pass");

  useEffect(() => {
    api<Data>(`/api/offices/${officeId}/findings`).then(setData).catch((e) => setError(e.message));
  }, [officeId]);

  const rows = useMemo(
    () =>
      (data?.results ?? []).filter(
        (r) => (product === "all" || r.product.toUpperCase() === product) && (status === "all" || (status === "not-pass" ? r.status !== "pass" : r.status === status)),
      ),
    [data, product, status],
  );

  if (error) return <div className="error">{error}</div>;
  if (!data) return <div className="muted">Loading…</div>;

  return (
    <>
      <h1>Microsoft 365 security checks</h1>
      <p className="lead">
        Your Microsoft 365 settings checked against the US government's security baseline (CISA SCuBA). "Must fix" items are required;
        "Recommended" items are good practice. "Could not check" means the data was not available, never a failure.
      </p>
      {data.results.length === 0 ? (
        <div className="card">
          <p>No SCuBA results yet.</p>
          <p className="muted">They appear after the next collection (Microsoft 365 consent with the updated permissions) or after a ScubaGear report is uploaded in step 5.</p>
        </div>
      ) : (
        <>
          <table>
            <thead><tr><th>Area</th><th>OK</th><th>Must fix</th><th>Recommended</th><th>Not applicable</th><th>Could not check</th></tr></thead>
            <tbody>
              {Object.entries(data.summary).map(([p, s]) => (
                <tr key={p}>
                  <td><button className="secondary" onClick={() => setProduct(product === p ? "all" : p)}>{PRODUCT[p] ?? p}</button></td>
                  <td>{s.pass ?? 0}</td><td><strong>{s.fail ?? 0}</strong></td><td>{s.warning ?? 0}</td><td>{s.na ?? 0}</td><td>{s.error ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="row" style={{ margin: "1rem 0" }}>
            <label htmlFor="f-status" style={{ margin: 0 }}>Show</label>
            <select id="f-status" value={status} onChange={(e) => setStatus(e.target.value)} style={{ maxWidth: 220 }}>
              <option value="not-pass">Everything not passing</option>
              <option value="fail">Must fix</option>
              <option value="warning">Recommended</option>
              <option value="error">Could not check</option>
              <option value="pass">OK</option>
              <option value="all">All</option>
            </select>
            <span className="muted">{product === "all" ? "All products" : PRODUCT[product] ?? product} · {rows.length} policies</span>
          </div>
          <p className="muted" style={{ fontSize: "0.9em" }}>Press <strong>!</strong> for why it matters and the official CISA wording.</p>
          {rows.map((r) => <PolicyCard key={`${r.product}-${r.policy_id}`} r={r} />)}
        </>
      )}
    </>
  );
}
