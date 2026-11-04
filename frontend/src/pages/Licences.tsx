import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { InfoButton } from "../components/Plain";
import Export from "./Export";

type Product = {
  part: string;
  name: string;
  bought: number;
  assigned: number;
  unassigned: number;
  free: boolean;
  price: number | null;
  price_source: "yours" | "list" | null;
  monthly: number | null;
};
type Person = { upn: string; licences: string[]; reasons: string[]; last_sign_in: string | null; monthly: number };
type Security = { key: string; feature: string; included_in: string[]; in_use: boolean | null; note: string };
type View = {
  as_of: string;
  products: Product[];
  people: Person[];
  security: Security[];
  totals: {
    paid_licences: number;
    assigned: number;
    unassigned: number;
    monthly_spend: number;
    unpriced: string[];
    monthly_unassigned: number;
    monthly_review: number;
    people_to_review: number;
  };
  read: { users: boolean; sign_ins: boolean; usage: boolean; usage_concealed: boolean };
};

const money = (n: number | null) => (n == null ? "—" : `$${n.toLocaleString(undefined, { maximumFractionDigits: 0 })}`);

function PriceCell({ p, onSave }: { p: Product; onSave: (part: string, v: number | null) => Promise<void> }) {
  const [edit, setEdit] = useState(false);
  const [v, setV] = useState(p.price?.toString() ?? "");
  if (p.free) return <span className="muted">Free</span>;
  if (!edit) {
    return (
      <span>
        {p.price == null ? <span className="muted">Not set</span> : `$${p.price}`}{" "}
        {p.price_source === "list" && <span className="muted" style={{ fontSize: "0.8em" }}>(list price)</span>}{" "}
        <button className="secondary" style={{ padding: "0.1rem 0.5rem", fontSize: "0.8em" }} onClick={() => setEdit(true)}>Edit</button>
      </span>
    );
  }
  return (
    <span className="row" style={{ gap: "0.3rem" }}>
      <input type="text" value={v} onChange={(e) => setV(e.target.value)} style={{ width: 80 }} aria-label={`Price for ${p.name}`} />
      <button style={{ padding: "0.2rem 0.6rem" }} onClick={() => onSave(p.part, v.trim() === "" ? null : Number(v)).then(() => setEdit(false))}>Save</button>
    </span>
  );
}

function PersonRow({ x }: { x: Person }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr>
        <td>{x.upn}</td>
        <td>{x.reasons[0]}{x.reasons.length > 1 && <span className="muted"> (+{x.reasons.length - 1})</span>}</td>
        <td className="muted">{x.licences.join(", ")}</td>
        <td>{money(x.monthly)}</td>
        <td><InfoButton on={open} toggle={() => setOpen(!open)} label="All reasons" /></td>
      </tr>
      {open && (
        <tr>
          <td colSpan={5} className="muted" style={{ fontSize: "0.9em" }}>
            {x.reasons.join(" · ")}
            {x.last_sign_in && ` · last sign-in ${new Date(x.last_sign_in).toLocaleDateString()}`}
          </td>
        </tr>
      )}
    </>
  );
}

export default function Licences() {
  const { officeId = "" } = useParams();
  const [v, setV] = useState<View | null>(null);
  const [error, setError] = useState("");
  const [all, setAll] = useState(false);
  const load = () => api<View>(`/api/offices/${officeId}/licences`).then(setV).catch((e) => setError(e.message));
  useEffect(() => {
    setV(null);
    setError("");
    load();
  }, [officeId]);
  const save = async (part: string, price: number | null) => {
    await api(`/api/offices/${officeId}/licence-prices`, { method: "PUT", body: JSON.stringify({ prices: { [part]: price } }) });
    await load();
  };

  const head = (
    <div className="row" style={{ justifyContent: "space-between" }}>
      <div><div className="page-role">Licences · Microsoft 365</div><h1>Licences</h1></div>
      {v && <Export officeId={officeId} what="licences" />}
    </div>
  );
  if (error) return <>{head}<div className="banner warn">{error}</div></>;
  if (!v) return <>{head}<div className="muted">Loading…</div></>;
  const t = v.totals;
  const waste = t.monthly_unassigned + t.monthly_review;
  const idle = v.security.filter((s) => s.in_use === false);
  const people = all ? v.people : v.people.slice(0, 15);

  return (
    <>
      {head}
      <p className="lead">
        What you buy from Microsoft, who holds it, and the security it already includes. Prices start at Microsoft's list price; enter your
        own to match your contract. <Link to={`/offices/${officeId}/remediation`}>Action plan</Link>
      </p>

      <div className={`banner ${waste > 0 ? "warn" : "good"}`}>
        <strong>
          {waste > 0
            ? `About ${money(waste)} a month to review: ${t.unassigned} seats nobody uses and ${t.people_to_review} people whose licence may not be needed.`
            : "No unused seats or licences to review."}
        </strong>
        {idle.length > 0 && <div style={{ marginTop: "0.3rem" }}>{idle.length} security feature(s) you pay for are not switched on.</div>}
      </div>

      <div className="stats">
        <div className="stat"><div className="n">{money(t.monthly_spend)}</div><div className="l">a month on paid licences{t.unpriced.length ? ` (${t.unpriced.length} without a price)` : ""}</div></div>
        <div className="stat"><div className="n">{t.assigned}<span style={{ fontSize: "1rem", color: "var(--muted)" }}> / {t.paid_licences}</span></div><div className="l">paid seats in use</div></div>
        <div className={`stat ${t.unassigned ? "warn" : "good"}`}><div className="n">{t.unassigned}</div><div className="l">seats bought but not given to anyone ({money(t.monthly_unassigned)}/month)</div></div>
        <div className={`stat ${t.people_to_review ? "warn" : "good"}`}><div className="n">{t.people_to_review}</div><div className="l">people to review ({money(t.monthly_review)}/month)</div></div>
        <div className={`stat ${idle.length ? "bad" : "good"}`}><div className="n">{idle.length}</div><div className="l">security features paid for, not switched on</div></div>
      </div>

      <h2>Security you already pay for</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Several security tools come inside Microsoft licences. Check what you have before buying, or paying twice for, the same thing.
      </p>
      <table>
        <thead><tr><th>Protection</th><th>Comes with</th><th>Switched on?</th><th>What we see</th></tr></thead>
        <tbody>
          {v.security.map((s) => (
            <tr key={s.key}>
              <td>{s.feature}</td>
              <td className="muted">{s.included_in.join(", ")}</td>
              <td><span className={`pill ${s.in_use === true ? "pass" : s.in_use === false ? "fail" : ""}`}>{s.in_use === true ? "Yes" : s.in_use === false ? "No" : "Not checked yet"}</span></td>
              <td className="muted">{s.note}</td>
            </tr>
          ))}
          {v.security.length === 0 && <tr><td colSpan={4} className="muted">No security add-ons found in your licences.</td></tr>}
        </tbody>
      </table>

      <h2>Products</h2>
      <table>
        <thead><tr><th>Product</th><th>Bought</th><th>In use</th><th>Unused</th><th>Price per user / month</th><th>Per month</th></tr></thead>
        <tbody>
          {v.products.map((p) => (
            <tr key={p.part} className={p.free ? "muted" : undefined}>
              <td>{p.name}<div className="muted" style={{ fontSize: "0.78em" }}><code>{p.part}</code></div></td>
              <td>{p.free ? "—" : p.bought}</td>
              <td>{p.assigned}</td>
              <td>{p.unassigned ? <span className="pill warn">{p.unassigned}</span> : "0"}</td>
              <td><PriceCell p={p} onSave={save} /></td>
              <td>{money(p.monthly)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>People to review</h2>
      {!v.read.sign_ins && (
        <div className="banner warn" style={{ fontSize: "0.95rem" }}>
          Sign-in dates were not readable (they need Entra ID P1 or P2), so nobody is listed as inactive.
        </div>
      )}
      {v.read.usage_concealed && (
        <div className="banner warn" style={{ fontSize: "0.95rem" }}>
          Microsoft 365 reports hide user names in this tenant, so app usage cannot be matched to people. An admin can turn off "Display
          concealed user, group, and site names" in the Microsoft 365 admin center (Settings, Org settings, Reports).
        </div>
      )}
      {v.people.length === 0 ? (
        <p className="muted">Nobody to review.</p>
      ) : (
        <>
          <table>
            <thead><tr><th>User</th><th>Why</th><th>Licences</th><th>Per month</th><th></th></tr></thead>
            <tbody>{people.map((x) => <PersonRow key={x.upn} x={x} />)}</tbody>
          </table>
          {v.people.length > 15 && (
            <button className="secondary" style={{ marginTop: "0.5rem" }} onClick={() => setAll(!all)}>
              {all ? "Show fewer" : `Show all ${v.people.length}`}
            </button>
          )}
        </>
      )}
      <p className="muted" style={{ fontSize: "0.85em", marginTop: "1rem" }}>
        As of the scan on {new Date(v.as_of).toLocaleString()}. Check with the person's manager before removing a licence; mailboxes of
        removed licences are kept for 30 days.
      </p>
    </>
  );
}
