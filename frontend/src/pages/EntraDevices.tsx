import { Fragment, useEffect, useState } from "react";
import { api, EntraSummary } from "../api";
import Export from "./Export";

type Rec = { name: string; os: string; os_version: string | null; join: string; managed: boolean; compliant: boolean; activity: string; last_sign_in: string | null; registered: string | null };
type Repeat = { name: string; records: number; reason: string; keep: string | null; items: Rec[] };
type View = {
  as_of: string;
  summary: EntraSummary;
  repeats: Repeat[];
  edr: { company_computers_active: number; with_edr: number; without_edr: Rec[]; edr_only: string[] } | null;
};

const ACT: Record<string, [string, string]> = {
  active: ["Active", "signed in within 30 days"],
  recent: ["Recent", "31 to 90 days"],
  stale: ["Stale", "no sign-in for over 90 days"],
  never: ["Never signed in", "no sign-in recorded"],
};
const JOIN_NOTE: Record<string, string> = {
  "Entra joined": "company computers joined to Entra ID",
  "Hybrid joined": "company computers joined to on-premises AD and Entra ID",
  Registered: "personal or user-added devices: phones, tablets, home PCs",
};
const day = (s: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "never");

function Counts({ title, data, note }: { title: string; data: Record<string, number>; note?: Record<string, string> }) {
  return (
    <div style={{ flex: "1 1 240px" }}>
      <h3>{title}</h3>
      <table>
        <tbody>
          {Object.entries(data).map(([k, v]) => (
            <tr key={k}><td>{k}{note?.[k] && <div className="muted" style={{ fontSize: "0.8em" }}>{note[k]}</div>}</td><td style={{ textAlign: "right" }}>{v}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Entra ID device records: why the count is high, repeated names, and the check against the EDR register. */
export default function EntraDevices({ officeId }: { officeId: string }) {
  const [v, setV] = useState<View | null>(null);
  const [missing, setMissing] = useState(false);
  const [all, setAll] = useState(false);
  const [open, setOpen] = useState("");
  useEffect(() => {
    api<View>(`/api/offices/${officeId}/entra-devices`).then(setV).catch(() => setMissing(true));
  }, [officeId]);

  if (missing) return <p className="muted">The breakdown of these records arrives with the next scan.</p>;
  if (!v) return null;
  const s = v.summary;
  const act = s.activity!;
  const repeats = all ? v.repeats : v.repeats.slice(0, 15);
  return (
    <>
      <div className="row" style={{ justifyContent: "space-between", marginTop: "1.5rem" }}>
        <h2>Devices in Entra ID</h2>
        <Export officeId={officeId} what="entra-devices" />
      </div>
      <p className="lead">
        Entra ID keeps a record for every device that ever joined or registered: replaced and reimaged PCs, phones with Outlook or Teams, and
        personal devices. It never removes one on its own, so {s.total} records is not {s.total} machines. Of them, {act.active} signed in
        within 30 days, and {s.company_computers_active} are active company computers (Windows or Mac, joined).
      </p>
      <div className="stats">
        <div className="stat good"><div className="n">{act.active}</div><div className="l">active (signed in within 30 days)</div></div>
        <div className="stat"><div className="n">{s.company_computers_active}</div><div className="l">active company computers</div></div>
        <div className="stat warn"><div className="n">{act.stale + act.never}</div><div className="l">stale or never used: clean-up candidates</div></div>
        <div className="stat warn"><div className="n">{s.extra_records}</div><div className="l">extra records from repeated names</div></div>
        {v.edr && (
          <div className={`stat ${v.edr.without_edr.length ? "bad" : "good"}`}>
            <div className="n">{v.edr.without_edr.length}</div><div className="l">active company computers not in the EDR register</div>
          </div>
        )}
      </div>
      <details>
        <summary className="muted">Breakdown by activity, join type and operating system</summary>
      <div className="row" style={{ alignItems: "flex-start", gap: "1.5rem" }}>
        <Counts title="Activity" data={Object.fromEntries(Object.entries(ACT).map(([k, [l]]) => [l, act[k as keyof typeof act]]))} note={Object.fromEntries(Object.values(ACT))} />
        <Counts title="Join type" data={s.join!} note={JOIN_NOTE} />
        <Counts title="Operating system" data={s.os!} />
        <Counts title="Management" data={{ "Intune managed": s.managed, Compliant: s.compliant }} />
      </div>
      </details>

      <h3>Company computers and the EDR register</h3>
      {v.edr ? (
        <>
          <p>
            {v.edr.with_edr} of {v.edr.company_computers_active} active company computers are in the EDR register.{" "}
            {v.edr.without_edr.length > 0 && <span className="pill fail">{v.edr.without_edr.length} not in it</span>}{" "}
            {v.edr.edr_only.length > 0 && <span className="muted">{v.edr.edr_only.length} EDR hosts are not active company computers in Entra (servers, unjoined or retired machines).</span>}
          </p>
          {v.edr.without_edr.length > 0 && (
            <table>
              <thead><tr><th>Active in Entra, not in the EDR register</th><th>OS</th><th>Join type</th><th>Last sign-in</th></tr></thead>
              <tbody>
                {v.edr.without_edr.map((r) => (
                  <tr key={r.name}><td>{r.name}</td><td>{r.os} {r.os_version}</td><td>{r.join}</td><td>{day(r.last_sign_in)}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="muted" style={{ fontSize: "0.85em" }}>Matched by host name. A computer listed here has no sensor, or its name differs between Entra and the EDR console.</p>
        </>
      ) : (
        <p className="muted">Upload the EDR host export (onboarding step 5) to check which active computers have a sensor.</p>
      )}

      <h3>Repeated names ({v.repeats.length} names, {s.extra_records} extra records)</h3>
      <p className="muted">Each name with more than one record, with the most likely reason. The newest record is the one in use; the others are clean-up candidates in Entra ID (Devices, then filter by activity).</p>
      <table>
        <thead><tr><th>Name</th><th>Records</th><th>Why</th><th>Newest sign-in</th></tr></thead>
        <tbody>
          {repeats.map((g) => (
            <Fragment key={g.name}>
              <tr onClick={() => setOpen(open === g.name ? "" : g.name)} style={{ cursor: "pointer" }}>
                <td>{open === g.name ? "▾" : "▸"} {g.name}</td><td>{g.records}</td><td>{g.reason}</td><td>{day(g.keep)}</td>
              </tr>
              {open === g.name && g.items.map((r, i) => (
                <tr key={`${g.name}-${i}`} className="muted" style={{ fontSize: "0.85em" }}>
                  <td style={{ paddingLeft: "1.5rem" }}>{i === 0 ? "in use" : "older record"}</td>
                  <td>{r.join}</td>
                  <td>{r.os} {r.os_version} · registered {day(r.registered)} · {r.managed ? "Intune managed" : "not managed"}</td>
                  <td>{day(r.last_sign_in)}</td>
                </tr>
              ))}
            </Fragment>
          ))}
          {v.repeats.length === 0 && <tr><td colSpan={4} className="muted">No repeated names.</td></tr>}
        </tbody>
      </table>
      {v.repeats.length > 15 && <button className="secondary" onClick={() => setAll(!all)}>{all ? "Show fewer" : `Show all ${v.repeats.length}`}</button>}
    </>
  );
}
