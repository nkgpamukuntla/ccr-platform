import { useState } from "react";
import { EmailAuth, Intune, SecureScore } from "../api";
import { InfoButton } from "../components/Plain";

const NOT_READ = "Not checked yet. Reading this needs the added Microsoft permission (re-consent in onboarding step 4) and an Intune licence.";

/** Intune: the managed devices, their encryption and compliance. */
export function IntuneSection({ it }: { it: Intune | null | undefined }) {
  const [open, setOpen] = useState(false);
  if (!it) {
    return (
      <>
        <h2>Managed devices (Intune)</h2>
        <div className="banner warn" style={{ fontSize: "0.95rem" }}>{NOT_READ}</div>
      </>
    );
  }
  const tone = it.unencrypted || it.windows10 ? "bad" : it.noncompliant || it.stale ? "warn" : "good";
  return (
    <>
      <h2 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
        Managed devices (Intune) <InfoButton on={open} toggle={() => setOpen(!open)} label="Which devices" />
      </h2>
      <div className={`banner ${tone}`} style={{ fontSize: "0.98rem" }}>
        {it.total} devices are managed by Intune: {it.encrypted} of {it.computers} computers encrypted, {it.compliant} meet your security rules
        {it.policies === 0 ? " (no compliance rules are set yet)" : ""}.
      </div>
      <div className="stats">
        <div className="stat"><div className="n">{it.total}</div><div className="l">managed devices ({it.computers} computers)</div></div>
        <div className={`stat ${it.unencrypted ? "bad" : "good"}`}><div className="n">{it.unencrypted}</div><div className="l">computers not encrypted</div></div>
        <div className={`stat ${it.noncompliant ? "warn" : "good"}`}><div className="n">{it.noncompliant}</div><div className="l">fail your security rules</div></div>
        <div className={`stat ${it.windows10 ? "bad" : "good"}`}><div className="n">{it.windows10}</div><div className="l">on Windows 10</div></div>
        <div className={`stat ${it.stale ? "warn" : "quiet"}`}><div className="n">{it.stale}</div><div className="l">not checked in for 30 days</div></div>
        <div className="stat quiet"><div className="n">{it.personal}</div><div className="l">personal devices</div></div>
      </div>
      {open && (
        <div className="card" style={{ fontSize: "0.92em" }}>
          <p style={{ marginTop: 0 }}>By system: {Object.entries(it.by_os).map(([k, n]) => `${k} ${n}`).join(" · ")}</p>
          {(["unencrypted", "noncompliant", "windows10", "stale"] as const).map(
            (k) =>
              it.sample[k].length > 0 && (
                <p key={k}>
                  <strong>{{ unencrypted: "Not encrypted", noncompliant: "Fail the rules", windows10: "Windows 10", stale: "Not checked in" }[k]}:</strong>{" "}
                  {it.sample[k].join(", ")}
                </p>
              ),
          )}
        </div>
      )}
    </>
  );
}

const SPF: Record<string, [string, string]> = {
  ok: ["Set", "pass"],
  weak: ["Too open", "warn"],
  missing: ["Missing", "fail"],
  broken: ["Broken (two records)", "fail"],
  not_checked: ["Not checked", ""],
};
const DMARC: Record<string, [string, string]> = {
  reject: ["Rejects fakes", "pass"],
  quarantine: ["Sends fakes to junk", "pass"],
  none: ["Only watching", "warn"],
  missing: ["Missing", "fail"],
  not_checked: ["Not checked", ""],
};
const DKIM: Record<string, [string, string]> = { on: ["On", "pass"], not_found: ["Not found for Microsoft 365", ""], not_checked: ["Not checked", ""] };

/** SPF, DMARC and DKIM per domain, from public DNS. */
export function EmailSection({ em }: { em: EmailAuth | null | undefined }) {
  const [open, setOpen] = useState(false);
  if (!em) return null;
  const bad = em.unsafe.length;
  const loose = em.loose.length;
  const tone = bad ? "bad" : loose ? "warn" : "good";
  const cell = (m: Record<string, [string, string]>, v: string) => <span className={`pill ${m[v]?.[1] ?? ""}`}>{m[v]?.[0] ?? v}</span>;
  return (
    <>
      <h2 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
        Can someone send email as you? <InfoButton on={open} toggle={() => setOpen(!open)} label="The DNS records" />
      </h2>
      <div className={`banner ${tone}`} style={{ fontSize: "0.98rem" }}>
        {bad
          ? `${bad} of ${em.domains.length} domains can be faked: anyone can send email that looks like it comes from them.`
          : loose
            ? `${loose} of ${em.domains.length} domains only watch for fake email; it is still delivered.`
            : `All ${em.domains.length} domains reject fake email.`}
      </div>
      <table>
        <thead><tr><th>Domain</th><th>SPF (who may send)</th><th>DMARC (what happens to fakes)</th><th>DKIM (signed mail)</th></tr></thead>
        <tbody>
          {em.domains.map((d) => (
            <tr key={d.domain}>
              <td>{d.domain}</td>
              <td>{cell(SPF, d.spf)}</td>
              <td>{cell(DMARC, d.dmarc)}</td>
              <td>{cell(DKIM, d.dkim)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {open && (
        <div className="card muted" style={{ fontSize: "0.85em", marginTop: "0.5rem" }}>
          {em.domains.map((d) => (
            <div key={d.domain} style={{ marginBottom: "0.4rem" }}>
              <strong>{d.domain}</strong> · SPF: <code>{d.spf_record ?? "none"}</code> · DMARC: <code>{d.dmarc_record ?? "none"}</code>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

/** Microsoft's own score, as context; the biggest improvements first. */
export function SecureScoreSection({ ss }: { ss: SecureScore | null | undefined }) {
  const [open, setOpen] = useState(false);
  if (!ss) return null;
  return (
    <>
      <h2 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
        Microsoft Secure Score <InfoButton on={open} toggle={() => setOpen(!open)} label="Biggest improvements" />
      </h2>
      <div className="card">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
          <span style={{ fontSize: "1.6rem", fontWeight: 700 }}>{ss.percent ?? "—"}%</span>
          <span className="muted">
            {ss.current} of {ss.max} points{ss.all_tenants_average != null ? ` · average across Microsoft customers ${ss.all_tenants_average}` : ""}
          </span>
        </div>
        <div className="bar"><span style={{ width: `${ss.percent ?? 0}%` }} /></div>
        <p className="muted" style={{ fontSize: "0.88em", marginBottom: 0 }}>
          Microsoft's own score for your settings, shown for reference. Our checks above are what courts and insurers ask about.
        </p>
        {open && ss.top_actions.length > 0 && (
          <table style={{ marginTop: "0.75rem" }}>
            <thead><tr><th>Improvement</th><th>Points</th><th>Effect on staff</th></tr></thead>
            <tbody>
              {ss.top_actions.map((a) => (
                <tr key={a.title}><td>{a.title}</td><td>+{a.gain}</td><td className="muted">{a.impact ?? "—"}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
