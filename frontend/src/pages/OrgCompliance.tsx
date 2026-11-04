import { useEffect, useState } from "react";
import { api } from "../api";

export type Catalogue = {
  countries: { code: string; name: string }[];
  frameworks: { key: string; country: string; name: string; applies: string }[];
};
type Org = { id: string; name: string; countries: string[]; frameworks: string[]; group_frameworks: string[] };

/** Where an organisation operates and the frameworks it requires: per country, and in every office. */
export default function OrgCompliance({ org, canEdit, onSaved }: { org: Org; canEdit: boolean; onSaved: () => void }) {
  const [cat, setCat] = useState<Catalogue | null>(null);
  const [v, setV] = useState({ countries: org.countries, frameworks: org.frameworks, group_frameworks: org.group_frameworks });
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    api<Catalogue>("/api/frameworks").then(setCat);
  }, []);
  useEffect(() => {
    setV({ countries: org.countries, frameworks: org.frameworks, group_frameworks: org.group_frameworks });
  }, [org.id]);
  if (!cat) return null;

  const flip = (list: string[], x: string) => (list.includes(x) ? list.filter((y) => y !== x) : [...list, x]);
  // A country with none ticked uses all of its frameworks; show that as all ticked.
  const required = (key: string, country: string) => {
    const here = cat.frameworks.filter((f) => f.country === country).map((f) => f.key);
    return here.some((k) => v.frameworks.includes(k)) ? v.frameworks.includes(key) : true;
  };
  const toggleRequired = (key: string, country: string) => {
    const here = cat.frameworks.filter((f) => f.country === country).map((f) => f.key);
    const current = here.filter((k) => required(k, country));
    const next = flip(current, key);
    setV({ ...v, frameworks: [...v.frameworks.filter((k) => !here.includes(k)), ...(next.length === here.length ? [] : next)] });
  };
  const save = async () => {
    setError("");
    setMsg("");
    try {
      await api(`/api/workspaces/${org.id}/compliance`, { method: "PUT", body: JSON.stringify(v) });
      setMsg("Saved. Each office's Compliance page now follows this.");
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <div className="card" style={{ background: "var(--bg)" }}>
      <h3 style={{ marginTop: 0 }}>Countries and compliance for {org.name}</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        Choose the countries this organisation works in. Each office then picks its own country and gets that country's frameworks, plus any the
        organisation requires everywhere.
      </p>
      <strong>Countries</strong>
      <div className="choices" style={{ margin: "0.4rem 0 1rem" }}>
        {cat.countries.map((c) => (
          <button key={c.code} className={v.countries.includes(c.code) ? "on" : ""} disabled={!canEdit} onClick={() => setV({ ...v, countries: flip(v.countries, c.code) })}>
            <span className="cc">{c.code}</span> {c.name}
          </button>
        ))}
      </div>
      {v.countries.map((code) => (
        <div key={code} style={{ marginBottom: "0.75rem" }}>
          <strong><span className="cc">{code}</span> Offices in {cat.countries.find((c) => c.code === code)?.name}</strong>
          {cat.frameworks
            .filter((f) => f.country === code)
            .map((f) => (
              <label key={f.key} style={{ fontWeight: 400, display: "flex", gap: "0.5rem", alignItems: "baseline", margin: "0.3rem 0" }}>
                <input type="checkbox" checked={required(f.key, code)} disabled={!canEdit} onChange={() => toggleRequired(f.key, code)} />
                <span>{f.name} <span className="muted" style={{ fontSize: "0.85em" }}>· {f.applies}</span></span>
              </label>
            ))}
        </div>
      ))}
      <strong>Required in every office, whatever its country</strong>
      <div className="choices" style={{ margin: "0.4rem 0 1rem" }}>
        {cat.frameworks.map((f) => (
          <button key={f.key} className={v.group_frameworks.includes(f.key) ? "on" : ""} disabled={!canEdit} onClick={() => setV({ ...v, group_frameworks: flip(v.group_frameworks, f.key) })}>
            <span className="cc">{f.country}</span> {f.name}
          </button>
        ))}
      </div>
      {canEdit && <button onClick={save}>Save</button>}
      {msg && <span className="pill pass" style={{ marginLeft: "0.75rem" }}>{msg}</span>}
      {error && <div className="error">{error}</div>}
    </div>
  );
}
