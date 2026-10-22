import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, OfficeRow } from "../api";

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
};
type Data = { summary: Record<string, Record<string, number>>; results: Row[] };

const LABEL: Record<Row["status"], string> = { pass: "Pass", fail: "Fail", warning: "Warning", na: "N/A", error: "Error" };
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
      <h1>Findings · SCuBA baselines</h1>
      <p className="lead">
        Scored with CISA ScubaGear's own rules, by baseline policy. <strong>Collected</strong> = our read-only collection scored with ScubaGear's rules;{" "}
        <strong>Imported</strong> = a ScubaGear report the office ran and uploaded (onboarding step 5). An Error means the data was not available, never a failure.
      </p>
      {data.results.length === 0 ? (
        <div className="card">
          <p>No SCuBA results yet.</p>
          <p className="muted">They appear after the next collection (Microsoft 365 consent with the updated permissions) or after a ScubaGear report is uploaded in step 5.</p>
        </div>
      ) : (
        <>
          <table>
            <thead><tr><th>Product</th><th>Pass</th><th>Fail</th><th>Warning</th><th>N/A</th><th>Error</th></tr></thead>
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
              <option value="fail">Fail (SHALL not met)</option>
              <option value="warning">Warning (SHOULD not met)</option>
              <option value="error">Error (not observed)</option>
              <option value="pass">Pass</option>
              <option value="all">All</option>
            </select>
            <span className="muted">{product === "all" ? "All products" : PRODUCT[product] ?? product} · {rows.length} policies</span>
          </div>
          <table>
            <thead><tr><th>Policy</th><th>Requirement</th><th>Result</th><th>Reading</th><th>How established</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.product}-${r.policy_id}`}>
                  <td><code>{r.policy_id}</code><div className="muted">{r.criticality}</div></td>
                  <td>{r.requirement}</td>
                  <td><span className={`pill ${PILL[r.status]}`}>{LABEL[r.status]}</span></td>
                  <td className="muted" style={{ maxWidth: 320 }}>{r.details}</td>
                  <td className="muted">
                    {r.source === "collected" ? "Collected" : "Imported"} · ScubaGear {r.baseline}
                    <div>{new Date(r.assessed_at).toLocaleString()}</div>
                    {r.imported_by && <div>by {r.imported_by}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}
