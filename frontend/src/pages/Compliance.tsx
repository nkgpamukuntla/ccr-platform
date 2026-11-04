import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, OfficeRow, SecureScore } from "../api";
import { InfoButton } from "../components/Plain";

type Evidence = { key: string; label: string; state: string; note: string };
type Requirement = { clause: string; asks: string; state: string; evidence: Evidence[] };
type Framework = { key: string; country: string; name: string; applies: string; counts: Record<string, number>; requirements: Requirement[] };
type View = {
  as_of: string | null;
  countries: { code: string; name: string }[];
  jurisdictions: string[];
  frameworks: Framework[];
  deadlines: Record<string, { event: string; deadline: string }[]>;
  secure_score: SecureScore | null;
};

const PILL: Record<string, string> = { met: "pass", gap: "fail", weak: "warn", partly_checked: "warn", not_observed: "", pending: "" };
const LABEL: Record<string, string> = {
  met: "In place",
  gap: "Needs action",
  weak: "Partly in place",
  partly_checked: "Partly checked",
  not_observed: "Not checked yet",
  pending: "Needs your answer",
};
const Code = ({ c }: { c: string }) => <span className="cc">{c}</span>;

export function CompliancePicker() {
  const [rows, setRows] = useState<OfficeRow[]>([]);
  useEffect(() => {
    api<OfficeRow[]>("/api/offices").then(setRows);
  }, []);
  return (
    <>
      <h1>Compliance</h1>
      <p className="lead">Choose an office.</p>
      <table>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}><td><Link to={`/offices/${r.id}/compliance`}>{r.name}</Link></td><td>{r.county}</td></tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function RequirementRow({ r }: { r: Requirement }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`req ${r.state}`}>
      <div className="req-head">
        <span className="clause">{r.clause}</span>
        <span style={{ flex: 1 }}>{r.asks}</span>
        <span className={`pill ${PILL[r.state] ?? ""}`}>{LABEL[r.state] ?? r.state}</span>
        <InfoButton on={open} toggle={() => setOpen(!open)} label="What this is based on" />
      </div>
      {open && (
        <div className="req-body">
          {r.evidence.length === 0 ? (
            <p className="muted" style={{ margin: 0 }}>Microsoft 365 cannot show this. Your team answers it, with a document or screenshot as proof.</p>
          ) : (
            <table>
              <tbody>
                {r.evidence.map((e) => (
                  <tr key={e.key}>
                    <td>{e.label}</td>
                    <td><span className={`pill ${PILL[e.state] ?? ""}`}>{LABEL[e.state] ?? e.state}</span></td>
                    <td className="muted">{e.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

function FrameworkCard({ f }: { f: Framework }) {
  const n = f.requirements.length;
  const met = f.counts.met ?? 0;
  const bad = (f.counts.gap ?? 0) + (f.counts.weak ?? 0);
  return (
    <div className="card fw">
      <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
        <h3 style={{ margin: 0 }}><Code c={f.country} /> {f.name}</h3>
        <span className="muted">{met} of {n} in place{bad ? ` · ${bad} need attention` : ""}</span>
      </div>
      <div className="bar" style={{ margin: "0.5rem 0" }}>
        <span style={{ width: `${(100 * met) / n}%` }} />
      </div>
      <p className="muted" style={{ marginTop: 0, fontSize: "0.9em" }}>{f.applies}</p>
      {f.requirements.map((r, i) => <RequirementRow key={i} r={r} />)}
    </div>
  );
}

export default function Compliance() {
  const { officeId = "" } = useParams();
  const [v, setV] = useState<View | null>(null);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const load = () => api<View>(`/api/offices/${officeId}/compliance`).then(setV).catch((e) => setError(e.message));
  useEffect(() => {
    setV(null);
    load();
  }, [officeId]);

  const toggle = async (code: string) => {
    if (!v) return;
    const next = v.jurisdictions.includes(code) ? v.jurisdictions.filter((j) => j !== code) : [...v.jurisdictions, code];
    setSaving(true);
    setError("");
    try {
      await api(`/api/offices/${officeId}/jurisdictions`, { method: "PUT", body: JSON.stringify({ jurisdictions: next }) });
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  if (error && !v) return <div className="error">{error}</div>;
  if (!v) return <div className="muted">Loading…</div>;
  const all = v.frameworks.flatMap((f) => f.requirements);
  const count = (s: string) => all.filter((r) => r.state === s).length;
  const ss = v.secure_score;

  return (
    <>
      <div className="page-role">Compliance · by country</div>
      <h1>Compliance</h1>
      <p className="lead">
        Each country's rules, matched to what we checked in your environment. One check can count for several rules. This shows your
        evidence; it is not a certificate or legal advice. <Link to={`/offices/${officeId}/remediation`}>Action plan</Link>
      </p>

      <div className="card">
        <strong>Countries this office works in</strong>
        <div className="choices" style={{ marginTop: "0.5rem" }}>
          {v.countries.map((c) => (
            <button key={c.code} className={v.jurisdictions.includes(c.code) ? "on" : ""} disabled={saving} onClick={() => toggle(c.code)}>
              <Code c={c.code} /> {c.name}
            </button>
          ))}
        </div>
        {error && <div className="error">{error}</div>}
      </div>

      {v.jurisdictions.length === 0 ? (
        <div className="banner warn">Choose at least one country above to see its rules.</div>
      ) : (
        <>
          <div className="stats">
            <div className="stat good"><div className="n">{count("met")}</div><div className="l">rules in place</div></div>
            <div className="stat bad"><div className="n">{count("gap")}</div><div className="l">need action</div></div>
            <div className="stat warn"><div className="n">{count("weak") + count("partly_checked")}</div><div className="l">partly in place or partly checked</div></div>
            <div className="stat quiet"><div className="n">{count("pending") + count("not_observed")}</div><div className="l">need your answer or not checked yet</div></div>
            {ss && (
              <div className="stat">
                <div className="n">{ss.percent ?? "—"}%</div>
                <div className="l">Microsoft Secure Score ({ss.current} of {ss.max})</div>
              </div>
            )}
          </div>

          {v.frameworks.map((f) => <FrameworkCard key={f.key} f={f} />)}

          <h2>If something happens: reporting deadlines</h2>
          <div className="controls">
            {v.jurisdictions.map((j) => (
              <div className="card" key={j}>
                <h3 style={{ marginTop: 0 }}><Code c={j} /> {v.countries.find((c) => c.code === j)?.name}</h3>
                {(v.deadlines[j] ?? []).map((d) => (
                  <div key={d.event} style={{ marginBottom: "0.5rem" }}>
                    <strong>{d.event}</strong>
                    <div className="muted" style={{ fontSize: "0.92em" }}>{d.deadline}</div>
                  </div>
                ))}
              </div>
            ))}
          </div>
          <p className="muted" style={{ fontSize: "0.85em" }}>Deadlines are a reminder. Confirm with your legal adviser when an incident happens.</p>
        </>
      )}
    </>
  );
}
