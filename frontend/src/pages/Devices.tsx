import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";

type Template = { key: string; label: string; source: string; required: string[]; one_of: string[]; optional: string[] };
type Issue = { row: number | null; level: "error" | "warning"; message: string };
type Preview = { accepted: boolean; rows_total: number; rows_ok: number; rows_rejected: number; columns: Record<string, string>; issues: Issue[] };
type ImportRow = { id: string; template: string; filename: string; uploaded_by: string; uploaded_at: string; rows_loaded: number; rows_rejected: number; export_date: string | null };
type Device = { hostname: string | null; serial: string | null; os: string | null; sources: string[]; edr: string; managed: boolean; matched: boolean; site: string | null; last_seen: string | null };
type Register = { coverage: { devices: number; covered: number; uncovered: number }; matched: number; unmatched: number; devices: Device[] };

/** Step 5: upload a console export, see the validation, then accept it. Nothing is stored until Accept. */
export function CsvImport({ officeId, onLoaded }: { officeId: string; onLoaded?: () => void }) {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [tpl, setTpl] = useState("edr_hosts");
  const [file, setFile] = useState<File | null>(null);
  const [text, setText] = useState("");
  const [exportDate, setExportDate] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api<Template[]>("/api/import-templates").then(setTemplates);
  }, []);

  const check = async (f: File | undefined) => {
    setMsg("");
    setError("");
    setPreview(null);
    if (!f) return;
    setFile(f);
    const t = await f.text();
    setText(t);
    try {
      setPreview(await api<Preview>(`/api/offices/${officeId}/imports/preview?template=${tpl}`, { method: "POST", body: t, headers: { "Content-Type": "text/csv" } }));
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const accept = async () => {
    if (!file) return;
    try {
      const q = new URLSearchParams({ template: tpl, filename: file.name, ...(exportDate ? { export_date: exportDate } : {}) });
      const r = await api<{ rows_loaded: number; rows_rejected: number }>(`/api/offices/${officeId}/imports?${q}`, { method: "POST", body: text, headers: { "Content-Type": "text/csv" } });
      setMsg(`Imported ${r.rows_loaded} rows from ${file.name}${r.rows_rejected ? ` (${r.rows_rejected} rejected, listed above)` : ""}.`);
      setPreview(null);
      onLoaded?.();
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const t = templates.find((x) => x.key === tpl);

  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>Import a console export</h2>
      <div className="row">
        <select value={tpl} onChange={(e) => { setTpl(e.target.value); setPreview(null); }} style={{ maxWidth: 320 }}>
          {templates.map((x) => <option key={x.key} value={x.key}>{x.label}</option>)}
        </select>
        <a href={`/api/import-templates/${tpl}.csv`}>Download template</a>
      </div>
      {t && (
        <p className="muted">
          From: {t.source}. Needs: {[...t.required, ...(t.one_of.length ? [t.one_of.join(" or ")] : [])].join(", ") || "hostname or serial"}. Common vendor header names are accepted.
        </p>
      )}
      <label htmlFor="exp-date">Export date (optional)</label>
      <input id="exp-date" type="text" placeholder="2026-10-21" value={exportDate} onChange={(e) => setExportDate(e.target.value)} />
      <div style={{ marginTop: "0.75rem" }}>
        <input type="file" accept=".csv,text/csv" onChange={(e) => check(e.target.files?.[0])} />
      </div>
      {preview && (
        <div style={{ marginTop: "1rem" }}>
          <p>
            <span className={`pill ${preview.accepted ? "pass" : "fail"}`}>{preview.accepted ? "Valid" : "Rejected"}</span>{" "}
            {preview.rows_ok} of {preview.rows_total} rows OK, {preview.rows_rejected} rejected. Columns found: {Object.entries(preview.columns).map(([k, v]) => `${v} → ${k}`).join(", ")}
          </p>
          {preview.issues.length > 0 && (
            <table>
              <thead><tr><th>Row</th><th>Level</th><th>Issue</th></tr></thead>
              <tbody>
                {preview.issues.slice(0, 50).map((i, k) => (
                  <tr key={k}><td>{i.row ?? "file"}</td><td><span className={`pill ${i.level === "error" ? "fail" : "warn"}`}>{i.level}</span></td><td>{i.message}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          {preview.accepted && <div className="actions"><span /><button onClick={accept}>Accept file</button></div>}
        </div>
      )}
      {msg && <p><span className="pill pass">{msg}</span></p>}
      {error && <div className="error">{error}</div>}
    </div>
  );
}

export default function Devices() {
  const { officeId = "" } = useParams();
  const [reg, setReg] = useState<Register | null>(null);
  const [imports, setImports] = useState<ImportRow[]>([]);
  const [only, setOnly] = useState("all");
  const load = () => {
    api<Register>(`/api/offices/${officeId}/devices`).then(setReg);
    api<ImportRow[]>(`/api/offices/${officeId}/imports`).then(setImports);
  };
  useEffect(load, [officeId]);
  if (!reg) return <div className="muted">Loading…</div>;
  const rows = reg.devices.filter((d) => only === "all" || (only === "uncovered" ? d.edr !== "active" : !d.matched));
  return (
    <>
      <h1>Devices</h1>
      <p className="lead">Devices matched across sources (serial first, then hostname). Unmatched devices are listed, never dropped. <Link to="/offices">Back to offices</Link></p>
      <div className="row" style={{ marginBottom: "1rem" }}>
        <div className="card"><strong>{reg.coverage.devices}</strong><div className="muted">devices</div></div>
        <div className="card"><strong>{reg.coverage.covered} of {reg.coverage.devices}</strong><div className="muted">EDR active</div></div>
        <div className="card"><strong>{reg.matched}</strong><div className="muted">matched across sources</div></div>
        <div className="card"><strong>{reg.unmatched}</strong><div className="muted">seen in one source only</div></div>
      </div>
      <div className="row" style={{ marginBottom: "0.75rem" }}>
        <select value={only} onChange={(e) => setOnly(e.target.value)} style={{ maxWidth: 260 }}>
          <option value="all">All devices</option>
          <option value="uncovered">No active EDR agent</option>
          <option value="unmatched">Seen in one source only</option>
        </select>
      </div>
      <table>
        <thead><tr><th>Hostname</th><th>Serial</th><th>OS</th><th>EDR</th><th>Sources</th><th>Last seen</th></tr></thead>
        <tbody>
          {rows.map((d, i) => (
            <tr key={i}>
              <td>{d.hostname ?? "—"}</td><td>{d.serial ?? "—"}</td><td>{d.os ?? "—"}</td>
              <td><span className={`pill ${d.edr === "active" ? "pass" : "fail"}`}>{d.edr}</span></td>
              <td className="muted">{d.sources.map((s) => s.replace("import:", "")).join(", ")}</td>
              <td className="muted">{d.last_seen ? new Date(d.last_seen).toLocaleDateString() : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>Imported files</h2>
      <table>
        <thead><tr><th>File</th><th>Template</th><th>Rows</th><th>Uploaded</th></tr></thead>
        <tbody>
          {imports.map((f) => (
            <tr key={f.id}><td>{f.filename}</td><td>{f.template}</td><td>{f.rows_loaded} loaded{f.rows_rejected ? `, ${f.rows_rejected} rejected` : ""}</td><td className="muted">{new Date(f.uploaded_at).toLocaleString()} by {f.uploaded_by}</td></tr>
          ))}
        </tbody>
      </table>
      <div style={{ marginTop: "1.5rem" }}><CsvImport officeId={officeId} onLoaded={load} /></div>
    </>
  );
}
