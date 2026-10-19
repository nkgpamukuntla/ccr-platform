import { FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, OfficeRow, post } from "../api";
import { useMe } from "../App";

type Member = { email: string; role: string; added_at: string; added_by: string };
type Person = {
  email: string;
  status: string;
  enabled: boolean;
  groups: string[];
  offices: { office_id: string; office: string; role: string }[];
};

const ROLE_LABEL: Record<string, string> = {
  office_admin: "Office administrator",
  office_member: "Office member",
  aoc_viewer: "AOC viewer",
  platform_admin: "Platform administrator",
};
const STATUS_LABEL: Record<string, string> = {
  FORCE_CHANGE_PASSWORD: "Invited (not signed in yet)",
  CONFIRMED: "Active",
  NOT_IN_DIRECTORY: "Missing sign-in account",
};

function InviteForm({ offices, fixedOffice, allowAoc, onDone }: { offices: OfficeRow[]; fixedOffice?: string; allowAoc: boolean; onDone: () => void }) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("office_member");
  const [office, setOffice] = useState(fixedOffice ?? "");
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setMsg("");
    try {
      const r = await post<{ status: string }>("/api/members", { email, role, office_id: role === "aoc_viewer" ? null : office || null });
      setMsg(r.status === "invited" ? `Invited ${email}. Cognito has emailed them a temporary password.` : `${email} already had an account; access updated.`);
      setEmail("");
      onDone();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <form className="card" onSubmit={submit}>
      <h2 style={{ marginTop: 0 }}>Invite someone</h2>
      <label htmlFor="inv-email">Work email</label>
      <input id="inv-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="it-lead@county.example.gov" />
      <label htmlFor="inv-role">Role</label>
      <select id="inv-role" value={role} onChange={(e) => setRole(e.target.value)}>
        <option value="office_member">Office member</option>
        <option value="office_admin">Office administrator (can invite others)</option>
        {allowAoc && <option value="aoc_viewer">AOC viewer (all offices, read-only)</option>}
      </select>
      {role !== "aoc_viewer" && !fixedOffice && (
        <>
          <label htmlFor="inv-office">Office</label>
          <select id="inv-office" required value={office} onChange={(e) => setOffice(e.target.value)}>
            <option value="">Choose an office…</option>
            {offices.map((o) => (
              <option key={o.id} value={o.id}>{o.name} ({o.county})</option>
            ))}
          </select>
        </>
      )}
      {error && <div className="error">{error}</div>}
      {msg && <p><span className="pill pass">{msg}</span></p>}
      <div style={{ marginTop: "1rem" }}>
        <button type="submit">Send invitation</button>
      </div>
    </form>
  );
}

// ---------- platform administrators: everyone ----------
export function Users() {
  const me = useMe();
  const [people, setPeople] = useState<Person[] | null>(null);
  const [offices, setOffices] = useState<OfficeRow[]>([]);
  const [error, setError] = useState("");
  const load = () => api<Person[]>("/api/admin/users").then(setPeople).catch((e) => setError(e.message));
  useEffect(() => {
    load();
    api<OfficeRow[]>("/api/offices").then(setOffices);
  }, []);
  if (!me.is_admin) return <div className="error">Platform administrators only.</div>;
  return (
    <>
      <h1>Users</h1>
      <p className="lead">Everyone who can sign in, and what they can see. New users get a temporary password by email and set up MFA at first sign-in.</p>
      {error && <div className="error">{error}</div>}
      <table>
        <thead><tr><th>Email</th><th>Status</th><th>Access</th></tr></thead>
        <tbody>
          {people?.map((p) => (
            <tr key={p.email}>
              <td>{p.email}</td>
              <td><span className={`pill ${p.status === "CONFIRMED" ? "pass" : "warn"}`}>{STATUS_LABEL[p.status] ?? p.status}</span></td>
              <td>
                {p.groups.map((g) => <div key={g}>{ROLE_LABEL[g] ?? g}</div>)}
                {p.offices.map((o) => (
                  <div key={o.office_id}>
                    <Link to={`/offices/${o.office_id}/members`}>{o.office}</Link> · {ROLE_LABEL[o.role]}
                  </div>
                ))}
                {p.groups.length === 0 && p.offices.length === 0 && <span className="muted">No access yet</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div style={{ marginTop: "1.5rem" }}>
        <InviteForm offices={offices} allowAoc onDone={load} />
      </div>
    </>
  );
}

// ---------- one office: platform admins and the office's administrator ----------
export default function OfficeMembers() {
  const { officeId = "" } = useParams();
  const me = useMe();
  const [office, setOffice] = useState<OfficeRow | null>(null);
  const [rows, setRows] = useState<Member[] | null>(null);
  const [error, setError] = useState("");
  const load = () => api<Member[]>(`/api/offices/${officeId}/members`).then(setRows).catch((e) => setError(e.message));
  useEffect(() => {
    load();
    api<OfficeRow>(`/api/offices/${officeId}`).then(setOffice);
  }, [officeId]);

  const myRole = rows?.find((r) => r.email === me.email)?.role;
  const canManage = me.is_admin || myRole === "office_admin";
  const remove = async (email: string) => {
    if (!window.confirm(`Remove ${email} from this office? They lose access to it immediately.`)) return;
    try {
      await api(`/api/offices/${officeId}/members/${encodeURIComponent(email)}`, { method: "DELETE" });
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <>
      <h1>Members{office ? ` · ${office.name}` : ""}</h1>
      <p className="lead">People who can see and work on this office. <Link to="/offices">Back to offices</Link></p>
      {error && <div className="error">{error}</div>}
      <table>
        <thead><tr><th>Email</th><th>Role</th><th>Added</th><th></th></tr></thead>
        <tbody>
          {rows?.length === 0 && <tr><td colSpan={4} className="muted">No members yet.</td></tr>}
          {rows?.map((m) => (
            <tr key={m.email}>
              <td>{m.email}</td>
              <td>{ROLE_LABEL[m.role]}</td>
              <td className="muted">{new Date(m.added_at).toLocaleDateString()} by {m.added_by}</td>
              <td>{canManage && m.email !== me.email && <button className="secondary" onClick={() => remove(m.email)}>Remove</button>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {canManage && (
        <div style={{ marginTop: "1.5rem" }}>
          <InviteForm offices={[]} fixedOffice={officeId} allowAoc={false} onDone={load} />
        </div>
      )}
    </>
  );
}
