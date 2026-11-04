import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, OfficeRow, SecureScore } from "../api";
import { useMe } from "../App";
import { InfoButton } from "../components/Plain";

type Evidence = { key: string; label: string; state: string; note: string };
type Requirement = { clause: string; asks: string; state: string; evidence: Evidence[] };
type Framework = { key: string; country: string; name: string; applies: string; counts: Record<string, number>; requirements: Requirement[] };
type View = {
  as_of: string | null;
  country: string | null;
  countries: { code: string; name: string }[];
  organisation: { id: string; name: string; countries: string[]; frameworks: string[]; group_frameworks: string[] } | null;
  catalogue: { key: string; country: string; name: string }[];
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

  const me = useMe();
  const setCountry = async (code: string) => {
    setSaving(true);
    setError("");
    try {
      await api(`/api/offices/${officeId}/country`, { method: "PUT", body: JSON.stringify({ country: code }) });
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
      <div className="page-role">Compliance · by country and organisation</div>
      <h1>Compliance</h1>
      <p className="lead">
        The rules for this office's country and what its organisation requires, matched to what we checked. One check can count for several rules. This shows your
        evidence; it is not a certificate or legal advice. <Link to={`/offices/${officeId}/remediation`}>Action plan</Link>
      </p>

      {(() => {
        const org = v.organisation;
        const options = org && org.countries.length ? org.countries : v.countries.map((c) => c.code);
        const name = (c: string | null) => v.countries.find((x) => x.code === c)?.name ?? c;
        const group = v.catalogue.filter((f) => org?.group_frameworks.includes(f.key));
        return (
          <div className="card">
            <div className="row" style={{ justifyContent: "space-between" }}>
              <div>
                <strong>This office is in</strong>{" "}
                <select value={v.country ?? ""} disabled={saving} onChange={(e) => setCountry(e.target.value)} style={{ maxWidth: 220, display: "inline-block", marginLeft: "0.4rem" }}>
                  {!v.country && <option value="">Choose a country…</option>}
                  {options.map((c) => (
                    <option key={c} value={c}>{name(c)}</option>
                  ))}
                </select>
              </div>
              {org && (
                <span className="muted" style={{ fontSize: "0.9em" }}>
                  {org.name} works in {org.countries.length ? org.countries.map(name).join(", ") : "countries not set yet"}
                  {me.is_admin && <> · <Link to={`/workspaces/${org.id}`}>Change for the organisation</Link></>}
                </span>
              )}
            </div>
            {group.length > 0 && (
              <p className="muted" style={{ margin: "0.5rem 0 0", fontSize: "0.9em" }}>
                {org?.name} also requires in every office: {group.map((f) => f.name).join(", ")}.
              </p>
            )}
            {error && <div className="error">{error}</div>}
          </div>
        );
      })()}

      {!v.country ? (
        <div className="banner warn">Choose the office's country above to see the rules that apply.</div>
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
            {Object.keys(v.deadlines).map((j) => (
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
