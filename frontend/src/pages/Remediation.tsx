import { FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, OfficeRow, post } from "../api";
import { FindingCard } from "../components/Plain";
import Export from "./Export";

type Item = { id: string; status: string; owner: string; target_date: string | null };
type Finding = {
  key: string;
  title: string;
  area: string;
  control: number | null;
  severity: string;
  source: string;
  recommendation: string;
  as_of: string | null;
  evidence: Record<string, unknown>;
  why: string;
  technical: string;
  item: Item | null;
};
type Event = { at: string; actor: string; from_status: string | null; to_status: string; note: string | null };
type Tracked = {
  id: string;
  title: string;
  recommendation: string;
  owner: string;
  target_date: string | null;
  status: string;
  overdue: boolean;
  created_by: string;
  closed_at: string | null;
  closed_reason: string | null;
  events: Event[];
};
type Recipient = { id: string; email: string; events: string[]; added_by: string };
type Outbox = { event: string; recipient: string; subject: string; queued_at: string; sent_at: string | null; last_error: string | null };

const COLUMNS = [
  ["open", "Open"],
  ["in_progress", "In progress"],
  ["awaiting_evidence", "Awaiting evidence"],
  ["closed", "Closed"],
] as const;
const day = (s: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "—");

export function RemediationPicker() {
  const [rows, setRows] = useState<OfficeRow[]>([]);
  useEffect(() => {
    api<OfficeRow[]>("/api/offices").then(setRows);
  }, []);
  return (
    <>
      <h1>Remediation</h1>
      <p className="lead">Choose an office.</p>
      <table>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td><Link to={`/offices/${r.id}/remediation`}>{r.name}</Link></td>
              <td>{r.workspace}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function TrackForm({ officeId, f, done }: { officeId: string; f: Finding; done: () => void }) {
  const [owner, setOwner] = useState("");
  const [target, setTarget] = useState("");
  const [error, setError] = useState("");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await post(`/api/offices/${officeId}/remediation`, { finding_key: f.key, owner, target_date: target || null });
      done();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return (
    <form className="row" onSubmit={submit} style={{ marginTop: "0.4rem" }}>
      <input required placeholder="Owner (IT team, MSP, a name)" value={owner} onChange={(e) => setOwner(e.target.value)} style={{ maxWidth: 240 }} />
      <input type="date" aria-label="Target date" value={target} onChange={(e) => setTarget(e.target.value)} style={{ maxWidth: 160 }} />
      <button type="submit">Track</button>
      {error && <span className="error">{error}</span>}
    </form>
  );
}

function Card({ officeId, it, reload }: { officeId: string; it: Tracked; reload: () => void }) {
  const [open, setOpen] = useState(false);
  const [note, setNote] = useState("");
  const move = async (status: string) => {
    await api(`/api/offices/${officeId}/remediation/${it.id}`, { method: "PATCH", body: JSON.stringify({ status, note: note || null }) });
    setNote("");
    reload();
  };
  return (
    <div className="card" style={{ padding: "0.75rem", marginBottom: "0.6rem" }}>
      <strong>{it.title}</strong>
      <div className="muted" style={{ fontSize: "0.85em" }}>
        Owner: {it.owner} · Target: {day(it.target_date)} {it.overdue && <span className="pill fail">Overdue</span>}
      </div>
      {it.closed_reason && <div className="muted" style={{ fontSize: "0.85em" }}>{it.closed_reason}</div>}
      {it.status !== "closed" && (
        <div className="row" style={{ marginTop: "0.4rem", gap: "0.4rem" }}>
          <input placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} style={{ maxWidth: 200 }} />
          {COLUMNS.filter(([k]) => k !== "closed" && k !== it.status).map(([k, label]) => (
            <button key={k} className="secondary" onClick={() => move(k)}>{label}</button>
          ))}
        </div>
      )}
      <button className="secondary" style={{ marginTop: "0.4rem", fontSize: "0.8em" }} onClick={() => setOpen(!open)}>
        {open ? "Hide history" : `History (${it.events.length})`}
      </button>
      {open && (
        <ul className="muted" style={{ fontSize: "0.85em" }}>
          {it.events.map((e, i) => (
            <li key={i}>
              {new Date(e.at).toLocaleString()} · {e.actor} · {e.from_status ?? "new"} → {e.to_status}
              {e.note ? ` · ${e.note}` : ""}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Notifications({ officeId }: { officeId: string }) {
  const [data, setData] = useState<{ recipients: Recipient[]; recent: Outbox[]; sending_enabled: boolean } | null>(null);
  const [email, setEmail] = useState("");
  const [msg, setMsg] = useState("");
  const load = () => api<typeof data>(`/api/offices/${officeId}/notifications`).then(setData);
  useEffect(() => {
    load();
  }, [officeId]);
  const add = async (e: FormEvent) => {
    e.preventDefault();
    setMsg("");
    try {
      await post(`/api/offices/${officeId}/notifications`, { email, events: ["scan_report", "scan_failed"] });
      setEmail("");
      load();
    } catch (err) {
      setMsg((err as Error).message);
    }
  };
  const remove = async (r: Recipient) => {
    if (!confirm(`Stop emails to ${r.email}?`)) return;
    await api(`/api/offices/${officeId}/notifications/${r.id}`, { method: "DELETE" });
    load();
  };
  const sendNow = async () => {
    setMsg("");
    try {
      const r = await post<{ queued: number; sent?: number; held?: number; subject: string }>(`/api/offices/${officeId}/notifications/send-latest`);
      setMsg(r.sent ? `Sent to ${r.sent} recipient(s): "${r.subject}"` : `Queued for ${r.queued} recipient(s); sending starts once email is enabled.`);
      load();
    } catch (err) {
      setMsg((err as Error).message);
    }
  };
  if (!data) return null;
  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>Notifications</h2>
      <p className="muted">
        One email per scan, after it is scored: the findings summary and what changed since the previous scan. A scan that fails all its
        retries sends one notice instead. Emails carry counts, titles and a link only; the evidence stays behind sign-in.
      </p>
      {!data.sending_enabled && <p className="pill warn">Email sending is not switched on yet: messages are queued and nothing leaves the platform.</p>}
      <table>
        <tbody>
          {data.recipients.map((r) => (
            <tr key={r.id}>
              <td>{r.email}</td>
              <td className="muted">{r.events.join(", ")} · added by {r.added_by}</td>
              <td><button className="secondary" onClick={() => remove(r)}>Remove</button></td>
            </tr>
          ))}
          {data.recipients.length === 0 && <tr><td className="muted">No recipients yet.</td></tr>}
        </tbody>
      </table>
      <form className="row" onSubmit={add} style={{ marginTop: "0.5rem" }}>
        <input type="email" required placeholder="name@company.com" value={email} onChange={(e) => setEmail(e.target.value)} style={{ maxWidth: 300 }} />
        <button type="submit">Add recipient</button>
        <button type="button" className="secondary" onClick={sendNow} disabled={data.recipients.length === 0}>Email the latest scan report now</button>
      </form>
      {msg && <p className="muted">{msg}</p>}
      {data.recent.length > 0 && (
        <>
          <h3>Recent emails</h3>
          <table>
            <tbody>
              {data.recent.map((m, i) => (
                <tr key={i}>
                  <td>{new Date(m.queued_at).toLocaleString()}</td>
                  <td>{m.recipient}</td>
                  <td>{m.subject}</td>
                  <td>{m.sent_at ? <span className="pill pass">Sent</span> : m.last_error ? <span className="pill fail" title={m.last_error}>Failed</span> : <span className="pill">Queued</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

export default function Remediation() {
  const { officeId = "" } = useParams();
  const [reg, setReg] = useState<{ findings: Finding[]; counts: Record<string, number>; tracked: number } | null>(null);
  const [items, setItems] = useState<Tracked[]>([]);
  const [tracking, setTracking] = useState("");
  const [error, setError] = useState("");
  const load = () => {
    api<typeof reg>(`/api/offices/${officeId}/register`).then(setReg).catch((e) => setError(e.message));
    api<Tracked[]>(`/api/offices/${officeId}/remediation`).then(setItems);
  };
  useEffect(load, [officeId]);

  return (
    <>
      <h1>Findings and remediation</h1>
      <p className="lead">
        Each problem we found, in plain words, with what to do about it. Assign one to give it an owner and a target date. Work is done in your own tools; an
        item closes only when the next scan, import or collector run no longer shows the finding. <Link to={`/offices/${officeId}/evidence`}>Evidence pack</Link>
      </p>
      {error && <div className="error">{error}</div>}

      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>What to fix {reg && <span className="muted">({reg.findings.length})</span>}</h2>
        <Export officeId={officeId} what="findings" />
      </div>
      {reg && reg.findings.length > 0 && (
        <div className="stats">
          <div className="stat bad"><div className="n">{reg.findings.filter((f) => f.severity === "Mandatory").length}</div><div className="l">must fix</div></div>
          <div className="stat warn"><div className="n">{reg.findings.filter((f) => f.severity === "High").length}</div><div className="l">important</div></div>
          <div className="stat"><div className="n">{reg.findings.filter((f) => f.item).length}</div><div className="l">being worked on</div></div>
          <div className="stat quiet"><div className="n">{reg.findings.filter((f) => !f.item).length}</div><div className="l">not yet assigned</div></div>
        </div>
      )}
      <p className="muted" style={{ fontSize: "0.9em" }}>Press <strong>!</strong> on any finding for why it matters, how we know, and the technical reference for IT.</p>
      {reg?.findings.map((f) => (
        <FindingCard
          key={f.key}
          f={f}
          side={
            f.item ? (
              <span className="pill">{COLUMNS.find(([k]) => k === f.item!.status)?.[1]} · {f.item.owner}</span>
            ) : tracking === f.key ? null : (
              <button className="secondary" onClick={() => setTracking(f.key)}>Assign</button>
            )
          }
        />
      ))}
      {tracking && reg?.findings.find((f) => f.key === tracking) && (
        <div className="card">
          <strong>Assign: {reg.findings.find((f) => f.key === tracking)!.title}</strong>
          <TrackForm officeId={officeId} f={reg.findings.find((f) => f.key === tracking)!} done={() => { setTracking(""); load(); }} />
          <button className="secondary" style={{ marginTop: "0.4rem" }} onClick={() => setTracking("")}>Cancel</button>
        </div>
      )}
      {reg?.findings.length === 0 && <div className="banner good">No findings in the current evidence.</div>}

      <div className="row" style={{ justifyContent: "space-between", marginTop: "1.5rem" }}>
        <h2>Remediation board</h2>
        <Export officeId={officeId} what="remediation" />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))", gap: "0.75rem" }}>
        {COLUMNS.map(([k, label]) => {
          const col = items.filter((i) => i.status === k);
          return (
            <div key={k}>
              <h3>{label} <span className="muted">({col.length})</span></h3>
              {col.map((it) => <Card key={it.id} officeId={officeId} it={it} reload={load} />)}
            </div>
          );
        })}
      </div>

      <Notifications officeId={officeId} />
    </>
  );
}
