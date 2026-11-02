import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, OfficeRow } from "../api";
import { FindingCard, methodText, PlainFinding } from "../components/Plain";
import Export from "./Export";

type Control = { control: number; name: string; answer: string; state: string; evidence: string; method: string; as_of: string | null };
type Pack = {
  label: string;
  office: { name: string; workspace: string; office_type: string; county: string };
  as_of: string | null;
  generated_at: string;
  generated_by: string;
  controls: Control[];
  findings: PlainFinding[];
  remediation: { open: number; overdue: number; closed: number; items: { title: string; owner: string; status: string; target_date: string | null; closed_reason: string | null }[] };
  devices: { total: number; edr_active: number };
  statement: string;
};

const DESTINATIONS = [
  ["management", "Management report"],
  ["irma", "ACCG-IRMA renewal"],
  ["aoc", "AOC connection agreement"],
] as const;
const ANSWER_PILL: Record<string, string> = { Yes: "pass", No: "fail", Partial: "warn", "Partial (weak method)": "warn" };
const day = (s: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "—");

export function EvidencePicker() {
  const [rows, setRows] = useState<OfficeRow[]>([]);
  useEffect(() => {
    api<OfficeRow[]>("/api/offices").then(setRows);
  }, []);
  return (
    <>
      <h1>Evidence pack</h1>
      <p className="lead">Choose an office.</p>
      <table>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td><Link to={`/offices/${r.id}/evidence`}>{r.name}</Link></td>
              <td>{r.workspace}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export default function Evidence() {
  const { officeId = "" } = useParams();
  const [dest, setDest] = useState("management");
  const [pack, setPack] = useState<Pack | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    setPack(null);
    api<Pack>(`/api/offices/${officeId}/evidence-pack?destination=${dest}`).then(setPack).catch((e) => setError(e.message));
  }, [officeId, dest]);

  return (
    <>
      <div className="no-print">
        <h1>Evidence pack</h1>
        <p className="lead">
          The same evidence, rendered for its reader. Each answer keeps how it was established and when. <Link to={`/offices/${officeId}/remediation`}>Findings and remediation</Link>
        </p>
        <div className="row" style={{ marginBottom: "1rem" }}>
          <select value={dest} onChange={(e) => setDest(e.target.value)} style={{ maxWidth: 280 }}>
            {DESTINATIONS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
          </select>
          <Export officeId={officeId} what="evidence-pack" query={`?destination=${dest}`} csv={false} />
          <button className="secondary" onClick={() => window.print()}>Print / Save as PDF</button>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      {!pack && !error && <div className="muted">Loading…</div>}
      {pack && (
        <div className="card print-sheet">
          <h2 style={{ marginTop: 0 }}>{pack.label}: {pack.office.name}</h2>
          <p className="muted">
            {pack.office.workspace} · {pack.office.office_type} · {pack.office.county}<br />
            Evidence as of {day(pack.as_of)} · generated {new Date(pack.generated_at).toLocaleString()} by {pack.generated_by}
          </p>
          <table>
            <thead><tr><th>Control</th><th>Answer</th><th>What we found</th><th>How we know</th><th>Date</th></tr></thead>
            <tbody>
              {pack.controls.map((c) => (
                <tr key={c.control}>
                  <td>{c.control} {c.name}</td>
                  <td><span className={`pill ${ANSWER_PILL[c.answer] ?? ""}`}>{c.answer}</span></td>
                  <td>{c.evidence}</td>
                  <td className="muted">{methodText(c.method)}</td>
                  <td>{day(c.as_of)}</td>
                </tr>
              ))}
              {pack.controls.length === 0 && <tr><td colSpan={5} className="muted">No scored scan yet.</td></tr>}
            </tbody>
          </table>
          <div className="stats" style={{ marginTop: "1rem" }}>
            <div className="stat good"><div className="n">{pack.controls.filter((c) => c.answer === "Yes").length}</div><div className="l">controls in place</div></div>
            <div className="stat bad"><div className="n">{pack.controls.filter((c) => c.answer === "No").length}</div><div className="l">controls not in place</div></div>
            <div className="stat warn"><div className="n">{pack.controls.filter((c) => c.answer.startsWith("Partial")).length}</div><div className="l">partly in place</div></div>
            {pack.devices.total > 0 && (
              <div className="stat"><div className="n">{pack.devices.edr_active} / {pack.devices.total}</div><div className="l">computers with active EDR</div></div>
            )}
          </div>
          {dest === "management" && (
            <>
              <h3>What to fix ({pack.findings.length})</h3>
              <p className="muted no-print" style={{ fontSize: "0.9em" }}>Press <strong>!</strong> on a finding for why it matters and the technical reference.</p>
              {pack.findings.map((f) => <FindingCard key={f.key} f={f} />)}
            </>
          )}
          <h3>Remediation</h3>
          <p>{pack.remediation.open} open, {pack.remediation.overdue} past target date, {pack.remediation.closed} closed on fresh evidence.</p>
          {pack.remediation.items.length > 0 && (
            <table>
              <tbody>
                {pack.remediation.items.map((i, n) => (
                  <tr key={n}><td>{i.title}</td><td>{i.owner}</td><td>{i.status.replace("_", " ")}</td><td>{i.closed_reason ?? (i.target_date ? `target ${day(i.target_date)}` : "")}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="muted" style={{ marginTop: "1rem" }}>{pack.statement}</p>
        </div>
      )}
    </>
  );
}
