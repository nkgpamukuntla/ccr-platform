import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, OfficeRow } from "../api";
import { methodText, SEV_LABEL, SEV_PILL } from "../components/Plain";
import Export from "./Export";

type Control = { control: number; name: string; question: string; answer: string; state: string; evidence: string; method: string; as_of: string | null };
type Plan = { title: string; priority: string; steps: number; assigned: number; next_target: string | null };
type Pack = {
  label: string;
  office: { name: string; workspace: string; office_type: string; county: string };
  as_of: string | null;
  generated_at: string;
  generated_by: string;
  controls: Control[];
  plan: Plan[];
  remediation: { open: number; overdue: number; closed: number; items: { title: string; owner: string; status: string; target_date: string | null; closed_reason: string | null }[] };
  devices: { total: number; edr_active: number };
  statement: string;
};

const DESTINATIONS = [
  ["management", "Management report", "For your leadership: the answers plus how the fixes are going."],
  ["irma", "ACCG-IRMA renewal", "For the insurance renewal questionnaire: the answers and their evidence."],
  ["aoc", "AOC connection agreement", "For the court connection agreement: the answers and their evidence."],
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
      <h1>Evidence</h1>
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
  const count = (f: (c: Control) => boolean) => pack?.controls.filter(f).length ?? 0;

  return (
    <>
      <div className="no-print">
        <div className="page-role">Evidence · what to show</div>
        <h1>Evidence</h1>
        <p className="lead">
          The answers a court or insurer asks for, each with what we found, how we know and when. Ready to print or send.{" "}
          <Link to={`/offices/${officeId}/remediation`}>Action plan</Link>
        </p>
        <div className="choices" style={{ marginBottom: "0.5rem" }}>
          {DESTINATIONS.map(([k, label]) => (
            <button key={k} className={dest === k ? "on" : ""} onClick={() => setDest(k)}>{label}</button>
          ))}
        </div>
        <p className="muted" style={{ fontSize: "0.9em" }}>{DESTINATIONS.find(([k]) => k === dest)?.[2]}</p>
        <div className="row" style={{ marginBottom: "1rem" }}>
          <Export officeId={officeId} what="evidence-pack" query={`?destination=${dest}`} csv={false} />
          <button className="secondary" onClick={() => window.print()}>Print / Save as PDF</button>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      {!pack && !error && <div className="muted">Loading…</div>}
      {pack && (
        <div className="card print-sheet">
          <h2 style={{ marginTop: 0 }}>{pack.label}</h2>
          <p style={{ margin: "0 0 0.25rem", fontSize: "1.05rem" }}><strong>{pack.office.name}</strong> · {pack.office.office_type} · {pack.office.county}</p>
          <p className="muted" style={{ marginTop: 0 }}>
            {pack.office.workspace} · evidence as of {day(pack.as_of)} · prepared {new Date(pack.generated_at).toLocaleString()} by {pack.generated_by}
          </p>

          <div className="stats">
            <div className="stat good"><div className="n">{count((c) => c.answer === "Yes")}</div><div className="l">answered Yes</div></div>
            <div className="stat bad"><div className="n">{count((c) => c.answer === "No")}</div><div className="l">answered No</div></div>
            <div className="stat warn"><div className="n">{count((c) => c.answer.startsWith("Partial"))}</div><div className="l">Partly</div></div>
            <div className="stat quiet"><div className="n">{count((c) => !["Yes", "No"].includes(c.answer) && !c.answer.startsWith("Partial"))}</div><div className="l">not yet established</div></div>
          </div>

          {pack.controls.map((c) => (
            <div className="qa" key={c.control}>
              <div className="q">{c.control}. {c.question}</div>
              <div className="a"><span className={`pill ${ANSWER_PILL[c.answer] ?? ""}`}>{c.answer}</span></div>
              <div className="found">{c.evidence}</div>
              <div className="how">How we know: {methodText(c.method)} · {day(c.as_of)}</div>
            </div>
          ))}
          {pack.controls.length === 0 && <p className="muted">No completed scan yet, so no answers can be given.</p>}

          {dest === "management" ? (
            <>
              <h3>How the fixes are going</h3>
              {pack.plan.length === 0 ? (
                <p>Nothing to fix in the current evidence.</p>
              ) : (
                <table>
                  <thead><tr><th>Recommendation</th><th>Priority</th><th>Steps assigned</th><th>Next target</th></tr></thead>
                  <tbody>
                    {pack.plan.map((t) => (
                      <tr key={t.title}>
                        <td>{t.title}</td>
                        <td><span className={`pill ${SEV_PILL[t.priority] ?? ""}`}>{SEV_LABEL[t.priority] ?? t.priority}</span></td>
                        <td>{t.assigned} of {t.steps}</td>
                        <td>{t.next_target ? day(t.next_target) : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              <p>{pack.remediation.open} steps open, {pack.remediation.overdue} past their target date, {pack.remediation.closed} closed and confirmed by a later scan.</p>
            </>
          ) : (
            pack.remediation.open > 0 && (
              <p>
                Work in progress: {pack.remediation.open} improvement steps are assigned with owners and target dates; {pack.remediation.closed} have
                been completed and confirmed by a later scan.
              </p>
            )
          )}
          <p className="muted" style={{ marginTop: "1rem", borderTop: "1px solid var(--line)", paddingTop: "0.75rem" }}>{pack.statement}</p>
        </div>
      )}
    </>
  );
}
