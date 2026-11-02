import { ReactNode, useState } from "react";

export const SEV_LABEL: Record<string, string> = { Mandatory: "Must fix", High: "Important", Medium: "Good practice" };
export const SEV_PILL: Record<string, string> = { Mandatory: "fail", High: "warn", Medium: "" };

/** "Connected · SCuBA v1.8.0 rules" -> words a non-technical reader follows. */
export function methodText(m: string): string {
  if (m.includes("SCuBA")) return "Read from Microsoft 365, checked against CISA's security baseline";
  if (m.startsWith("Connected")) return "Read from Microsoft 365";
  if (m.startsWith("Imported")) return "From an uploaded console export";
  if (m.startsWith("Collected")) return "Read by the collector on the computer";
  if (m === "Attested") return "Your team's answer";
  return m;
}

export function value(v: unknown): string {
  if (Array.isArray(v)) return v.map(value).join(", ");
  if (v && typeof v === "object") return Object.entries(v).map(([k, x]) => `${k.replace(/_/g, " ")} ${value(x)}`).join("; ");
  return String(v);
}

export function InfoButton({ on, toggle, label = "More details" }: { on: boolean; toggle: () => void; label?: string }) {
  return (
    <button type="button" className={`info-btn ${on ? "on" : ""}`} title={label} aria-label={label} aria-expanded={on} onClick={toggle}>
      !
    </button>
  );
}

export type PlainFinding = {
  key: string;
  title: string;
  severity: string;
  area: string;
  source: string;
  recommendation: string;
  as_of: string | null;
  why?: string;
  technical?: string;
  evidence?: Record<string, unknown>;
};

const day = (s: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "—");

/** One finding in plain words; the "!" opens why it matters, how we know and the technical reference. */
export function FindingCard({ f, extra, side }: { f: PlainFinding; extra?: ReactNode; side?: ReactNode }) {
  const [open, setOpen] = useState(false);
  const sample = Array.isArray(f.evidence?.sample) ? (f.evidence!.sample as string[]) : null;
  return (
    <div className={`finding ${f.severity}`}>
      <div className="head">
        <span className={`pill ${SEV_PILL[f.severity] ?? ""}`}>{SEV_LABEL[f.severity] ?? f.severity}</span>
        <div className="t">
          {f.title}
          <div className="do muted" style={{ fontWeight: 400 }}><strong style={{ color: "var(--ink)" }}>What to do:</strong> {f.recommendation}</div>
        </div>
        {side}
        <InfoButton on={open} toggle={() => setOpen(!open)} />
      </div>
      {open && (
        <dl className="more">
          {f.why && (<><dt>Why it matters</dt><dd>{f.why}</dd></>)}
          {sample && sample.length > 0 && (
            <><dt>Affected ({String(f.evidence!.devices ?? sample.length)})</dt><dd>{sample.join(", ")}{Number(f.evidence!.devices) > sample.length ? " …" : ""}</dd></>
          )}
          <dt>How we know</dt>
          <dd>{methodText(f.source)} · {f.area} · as of {day(f.as_of)}</dd>
          {f.technical && (<><dt>Technical reference (for IT)</dt><dd className="muted">{f.technical}</dd></>)}
          {extra}
        </dl>
      )}
    </div>
  );
}
