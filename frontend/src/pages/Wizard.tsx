import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useMe } from "../App";
import { api, Answers, Check, Connection, Office, post, Prerequisite, ProfileResult, put, Site } from "../api";

const STEPS = ["Organisation", "Environment", "Prerequisites", "Connect", "Import / Collect", "Validate"];

export default function Wizard() {
  const { officeId = "", step = "1" } = useParams();
  const n = Number(step);
  const [office, setOffice] = useState<Office | null>(null);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const reload = useCallback(() => {
    api<Office>(`/api/offices/${officeId}`).then(setOffice).catch((e) => setError(e.message));
  }, [officeId]);
  useEffect(reload, [reload]);

  const go = (s: number) => {
    reload();
    navigate(`/offices/${officeId}/onboarding/${s}`);
  };
  const done = office?.onboarding?.completed_steps ?? [];

  if (error) return <div className="error">{error}</div>;
  if (!office) return <div className="muted">Loading…</div>;

  return (
    <>
      <h1>{office.name}</h1>
      <p className="lead">
        {office.office_type} · {office.county} County {office.onboarding?.live_at && <span className="pill pass">Live</span>}
      </p>
      <nav className="steps">
        {STEPS.map((label, i) => (
          <Link key={label} to={`/offices/${officeId}/onboarding/${i + 1}`} className={`${i + 1 === n ? "current" : ""} ${done.includes(i + 1) ? "done" : ""}`}>
            {i + 1} {label}
          </Link>
        ))}
      </nav>
      {n === 1 && <Organisation office={office} next={() => go(2)} />}
      {n === 2 && <Environment officeId={officeId} next={() => go(3)} />}
      {n === 3 && <Prerequisites officeId={officeId} next={() => go(4)} />}
      {n === 4 && <Connect officeId={officeId} next={() => go(5)} />}
      {n === 5 && <ImportCollect officeId={officeId} next={() => go(6)} />}
      {n === 6 && <Validate officeId={officeId} live={!!office.onboarding?.live_at} onLive={reload} />}
    </>
  );
}

function useError() {
  const [error, setError] = useState("");
  const run = async (fn: () => Promise<unknown>) => {
    setError("");
    try {
      await fn();
      return true;
    } catch (e) {
      setError((e as Error).message);
      return false;
    }
  };
  return { error, run };
}

// ---------- 1 Organisation ----------
function Organisation({ office, next }: { office: Office; next: () => void }) {
  const [form, setForm] = useState({
    name: office.name,
    office_type: office.office_type,
    signatory_name: office.signatory_name ?? "",
    technical_contact: office.technical_contact ?? "",
  });
  const [sites, setSites] = useState<Site[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set(office.sites.map((s) => s.id)));
  const { error, run } = useError();

  useEffect(() => {
    api<Site[]>(`/api/sites?county=${encodeURIComponent(office.county)}`).then(setSites);
  }, [office.county]);

  const toggle = (id: string) => {
    const s = new Set(picked);
    s.has(id) ? s.delete(id) : s.add(id);
    setPicked(s);
  };
  const save = async () => {
    if (await run(() => put(`/api/offices/${office.id}/organisation`, { ...form, site_ids: [...picked] }))) next();
  };

  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>Tell us who is onboarding</h2>
      <label>Governed office</label>
      <input type="text" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
      <label>Authorised signatory</label>
      <input type="text" value={form.signatory_name} onChange={(e) => setForm({ ...form, signatory_name: e.target.value })} placeholder="Name and title" />
      <label>Technical contact</label>
      <input type="text" value={form.technical_contact} onChange={(e) => setForm({ ...form, technical_contact: e.target.value })} placeholder="it-lead@county.example.gov" />
      <h2>Sites from the register</h2>
      <p className="muted">Confirm the sites this office uses.</p>
      <table>
        <thead>
          <tr><th></th><th>Site</th><th>Address</th><th>Courts</th></tr>
        </thead>
        <tbody>
          {sites.length === 0 && <tr><td colSpan={4} className="muted">No sites in the register for {office.county} yet.</td></tr>}
          {sites.map((s) => (
            <tr key={s.id}>
              <td><input type="checkbox" checked={picked.has(s.id)} onChange={() => toggle(s.id)} aria-label={s.name} /></td>
              <td>{s.name}</td>
              <td>{s.address}</td>
              <td>{s.courts.join(" · ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {error && <div className="error">{error}</div>}
      <div className="actions"><span /><button onClick={save}>Next: environment →</button></div>
    </div>
  );
}

// ---------- 2 Environment ----------
const QUESTIONS: { key: keyof Answers; q: string; options: [string, string][] }[] = [
  { key: "m365", q: "Microsoft 365 tenant?", options: [["commercial", "Commercial"], ["gcc", "GCC"], ["none", "None"], ["unsure", "Not sure"]] },
  { key: "device_mgmt", q: "Device management?", options: [["intune", "Intune"], ["rmm", "RMM"], ["gpo", "GPO only"], ["none", "None"], ["unsure", "Not sure"]] },
  { key: "edr", q: "Endpoint protection?", options: [["crowdstrike", "CrowdStrike"], ["defender", "Defender"], ["sentinelone", "SentinelOne"], ["cortex", "Cortex"], ["other", "Other"], ["none", "None"], ["unsure", "Not sure"]] },
  { key: "it_admin", q: "Who administers IT?", options: [["county", "County IT"], ["msp", "MSP"], ["none", "No one"], ["unsure", "Not sure"]] },
  { key: "api_allowed", q: "Can APIs be used?", options: [["yes", "Yes"], ["export_only", "Export only"], ["unsure", "Not sure"]] },
];

function Environment({ officeId, next }: { officeId: string; next: () => void }) {
  const [answers, setAnswers] = useState<Answers>({ m365: "commercial", device_mgmt: "intune", edr: "crowdstrike", it_admin: "county", api_allowed: "yes" });
  const [result, setResult] = useState<ProfileResult | null>(null);
  const { error, run } = useError();

  useEffect(() => {
    api<{ answers?: Answers }>(`/api/offices/${officeId}/environment`).then((r) => r.answers && setAnswers(r.answers));
  }, [officeId]);
  useEffect(() => {
    post<ProfileResult>("/api/profile/preview", answers).then(setResult).catch(() => setResult(null));
  }, [answers]);

  const save = async () => {
    if (await run(() => put(`/api/offices/${officeId}/environment`, answers))) next();
  };

  return (
    <div className="grid2">
      <div className="card">
        {QUESTIONS.map(({ key, q, options }) => (
          <div key={key}>
            <label>{q}</label>
            <div className="choices">
              {options.map(([v, l]) => (
                <button key={v} type="button" className={answers[key] === v ? "on" : ""} onClick={() => setAnswers({ ...answers, [key]: v })}>
                  {l}
                </button>
              ))}
            </div>
          </div>
        ))}
        {error && <div className="error">{error}</div>}
        <div className="actions"><span /><button onClick={save}>Next: prerequisites →</button></div>
      </div>
      <div className="card">
        <h2 style={{ marginTop: 0 }}>Your onboarding path</h2>
        {result && (
          <>
            <table>
              <tbody>
                {result.path.map((p) => (
                  <tr key={p.source}>
                    <td>{p.label}</td>
                    <td><span className="pill">{p.mode}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p><strong>Profile {result.profile} · {result.profile_name}</strong><br /><span className="muted">Site effort: {result.site_effort}</span></p>
            {result.unsure.length > 0 && <p className="muted">"Not sure" answers are confirmed by the engineer in step 3.</p>}
          </>
        )}
      </div>
    </div>
  );
}

// ---------- 3 Prerequisites ----------
function Prerequisites({ officeId, next }: { officeId: string; next: () => void }) {
  const [items, setItems] = useState<Prerequisite[] | null>(null);
  const { error, run } = useError();
  useEffect(() => {
    run(() => api<Prerequisite[]>(`/api/offices/${officeId}/prerequisites`).then(setItems));
  }, [officeId]);
  const ack = async () => {
    if (await run(() => post(`/api/offices/${officeId}/prerequisites/ack`))) next();
  };
  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>What each engineer must have ready</h2>
      <p className="muted">Only the prerequisites for this office's path appear. Print or send this list before anyone starts connecting.</p>
      {error && <div className="error">{error}</div>}
      {items && (
        <table>
          <thead><tr><th>Area</th><th>Item</th><th>Who</th></tr></thead>
          <tbody>
            {items.map((i, k) => (
              <tr key={k}><td>{i.group}</td><td>{i.item}</td><td>{i.who}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="actions">
        <button className="secondary" onClick={() => window.print()}>Print / save as PDF</button>
        <button onClick={ack} disabled={!items}>Next: connect →</button>
      </div>
    </div>
  );
}

// ---------- 4 Connect ----------
function Connect({ officeId, next }: { officeId: string; next: () => void }) {
  const me = useMe();
  const [params] = useSearchParams();
  const [rows, setRows] = useState<Connection[] | null>(null);
  const [tenant, setTenant] = useState("");
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [msg, setMsg] = useState("");
  const { error, run } = useError();

  const load = () => run(() => api<Connection[]>(`/api/offices/${officeId}/connections`).then(setRows));
  useEffect(() => {
    load();
  }, [officeId]);

  // Intune and Defender are read through the Microsoft 365 consent: no key of their own.
  const COVERED = ["intune", "defender"];
  const order = (src: string) => (src === "microsoft365" ? 0 : COVERED.includes(src) ? 1 : 2);
  const connectRows = (rows?.filter((r) => r.mode === "connect") ?? []).sort((a, b) => order(a.source) - order(b.source));
  const msGranted = rows?.some((r) => r.source === "microsoft365" && r.consent_status === "granted") ?? false;
  const isConnected = (r: Connection) => r.consent_status === "granted" || r.has_credential || (COVERED.includes(r.source) && msGranted);
  const consent = (source: string) => run(() => post(`/api/offices/${officeId}/consents/${source}`, { tenant_ref: tenant || null })).then(load);
  const revoke = (source: string) => run(() => post(`/api/offices/${officeId}/consents/${source}/revoke`)).then(load);
  const storeKey = async (source: string) => {
    if (await run(() => put(`/api/offices/${officeId}/connections/${source}/credential`, { value: keys[source] ?? "" }))) {
      setKeys({ ...keys, [source]: "" });
      setMsg(`Stored the ${source} credential. It cannot be read back from this portal.`);
      load();
    }
  };
  const finish = async () => {
    if (await run(() => post(`/api/offices/${officeId}/connect/complete`))) next();
  };

  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>Connect read-only sources</h2>
      {error && <div className="error">{error}</div>}
      {msg && <div className="pill pass">{msg}</div>}
      {rows && connectRows.length === 0 && <p className="muted">Nothing on this office's path uses Connect. Continue to Import / Collect.</p>}
      {connectRows.map((r) => (
        <div key={r.source} className="card">
          <div className="row" style={{ justifyContent: "space-between" }}>
            <strong>{r.source}</strong>
            {isConnected(r) ? <span className="pill pass">Connected</span> : <span className="pill warn">Not connected</span>}
          </div>
          {r.source === "microsoft365" ? (
            <>
              <p className="muted">Read-only application permissions. Not requested: mail, files, Teams messages, any write permission.</p>
              <ul>{r.scopes.map((s) => <li key={s}><code>{s}</code></li>)}</ul>
              {r.consent_status === "granted" ? (
                <p>Consent granted {r.granted_at && new Date(r.granted_at).toLocaleString()} {r.tenant_ref && `by tenant ${r.tenant_ref}`}. <button className="secondary" onClick={() => revoke(r.source)}>Revoke record</button></p>
              ) : me.microsoft_configured ? (
                <>
                  {params.get("consent") === "refused" && <div className="error">Consent was not granted. A Global Administrator of the county's tenant must approve it.</div>}
                  <p>A Global Administrator of the county's tenant signs in at Microsoft and approves read-only access once. It can be revoked in the county's own tenant at any time.</p>
                  <a href={`/api/offices/${officeId}/consents/microsoft365/start`}><button type="button">Sign in and grant consent</button></a>
                </>
              ) : (
                <>
                  <label>Tenant ID or primary domain</label>
                  <input type="text" value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="county.onmicrosoft.com" />
                  <p className="muted">Phase 2 adds the Microsoft admin-consent sign-in here. For now this records the office's consent decision.</p>
                  <button onClick={() => consent(r.source)}>Record consent</button>
                </>
              )}
            </>
          ) : COVERED.includes(r.source) ? (
            <p className="muted">Read through the Microsoft 365 consent above. No key is needed.</p>
          ) : (
            <>
              <p className="muted">Read-only API key. It goes straight to the secrets vault and is never shown again. The EDR connectors arrive in build phase 4, so this can be added later.</p>
              <div className="row">
                <input type="password" autoComplete="off" value={keys[r.source] ?? ""} onChange={(e) => setKeys({ ...keys, [r.source]: e.target.value })} placeholder={r.has_credential ? "Replace the stored key" : "Paste the read-only key"} />
                <button onClick={() => storeKey(r.source)} disabled={(keys[r.source] ?? "").length < 8}>Store key</button>
              </div>
            </>
          )}
        </div>
      ))}
      <div className="actions"><span /><button onClick={finish}>Next: import / collect →</button></div>
    </div>
  );
}

// ---------- 5 Import / Collect ----------
function ImportCollect({ officeId, next }: { officeId: string; next: () => void }) {
  const [rows, setRows] = useState<Connection[]>([]);
  useEffect(() => {
    api<Connection[]>(`/api/offices/${officeId}/connections`).then(setRows);
  }, [officeId]);
  const other = rows.filter((r) => r.mode !== "connect");
  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>Files from the county's own tools, and the collector</h2>
      {other.length === 0 ? (
        <p className="muted">Everything on this path is connected by API.</p>
      ) : (
        <table>
          <thead><tr><th>Source</th><th>Mode</th><th>Status</th></tr></thead>
          <tbody>
            {other.map((r) => (
              <tr key={r.source}><td>{r.source}</td><td><span className="pill">{r.mode}</span></td><td className="muted">CSV templates and the signed collector arrive in phase 3</td></tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="actions"><span /><button onClick={next}>Next: validate →</button></div>
    </div>
  );
}

// ---------- 6 Validate ----------
function Validate({ officeId, live, onLive }: { officeId: string; live: boolean; onLive: () => void }) {
  const [res, setRes] = useState<{ ready: boolean; checks: Check[] } | null>(null);
  const { error, run } = useError();
  useEffect(() => {
    run(() => api<{ ready: boolean; checks: Check[] }>(`/api/offices/${officeId}/validate`).then(setRes));
  }, [officeId]);
  const goLive = async () => {
    if (await run(() => post(`/api/offices/${officeId}/go-live`))) onLive();
  };
  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>Readiness check</h2>
      {error && <div className="error">{error}</div>}
      {res && (
        <table>
          <thead><tr><th>Check</th><th>Result</th><th>Action</th></tr></thead>
          <tbody>
            {res.checks.map((c) => (
              <tr key={c.check}><td>{c.check}</td><td><span className={`pill ${c.result}`}>{c.result}</span></td><td>{c.action || "—"}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="muted">Warnings do not block go-live; missing data shows as Not observed, never as met.</p>
      <div className="actions"><span />{live ? <span className="pill pass">Live</span> : <button onClick={goLive} disabled={!res?.ready}>Go live</button>}</div>
    </div>
  );
}
