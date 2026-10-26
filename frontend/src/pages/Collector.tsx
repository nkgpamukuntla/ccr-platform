import { useEffect, useState } from "react";
import { api } from "../api";

type Download = { id: string; created_by: string; created_at: string; revoked_by: string | null; revoked_at: string | null; bundles: number };
type Bundle = { id: string; filename: string; uploaded_by: string; uploaded_at: string; hostname: string | null; edr_status: string; edr_product: string | null; issues: { message: string }[] };
type Status = { enabled: boolean; downloads: Download[]; bundles: Bundle[] };
type Result = { name: string; ok: boolean; text: string };

/** Step 5, Collect: download the signed collector for this office, then upload the .ccre bundles it writes. */
export function CollectorCard({ officeId, onLoaded, showHistory = false }: { officeId: string; onLoaded?: () => void; showHistory?: boolean }) {
  const [st, setSt] = useState<Status | null>(null);
  const [results, setResults] = useState<Result[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const load = () => {
    api<Status>(`/api/offices/${officeId}/collector/status`).then(setSt).catch((e) => setError((e as Error).message));
  };
  useEffect(load, [officeId]);

  const download = async () => {
    setError("");
    const res = await fetch(`/api/offices/${officeId}/collector/download`, { credentials: "same-origin" });
    if (!res.ok) {
      try {
        setError((await res.json()).detail);
      } catch {
        setError(res.statusText);
      }
      return;
    }
    const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") || "")?.[1] || "ccr-collector.zip";
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
    load();
  };

  const upload = async (files: FileList | null) => {
    if (!files?.length) return;
    setBusy(true);
    const out: Result[] = [];
    for (const f of Array.from(files)) {
      try {
        const r = await api<{ hostname: string; edr_status: string; edr_product: string | null; warnings: string[] }>(
          `/api/offices/${officeId}/collector/bundles?filename=${encodeURIComponent(f.name)}`,
          { method: "POST", body: await f.arrayBuffer(), headers: { "Content-Type": "application/octet-stream" } },
        );
        out.push({ name: f.name, ok: true, text: `${r.hostname}: EDR ${r.edr_status}${r.edr_product ? ` (${r.edr_product})` : ""}${r.warnings.length ? `. ${r.warnings.join("; ")}` : ""}` });
      } catch (e) {
        out.push({ name: f.name, ok: false, text: (e as Error).message });
      }
    }
    setResults(out);
    setBusy(false);
    load();
    onLoaded?.();
  };

  const revoke = async (id: string) => {
    if (!confirm("Revoke this download? Bundles it writes from now on will be refused.")) return;
    await api(`/api/offices/${officeId}/collector/downloads/${id}/revoke`, { method: "POST" });
    load();
  };

  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>Collect with the offline collector</h2>
      <p className="muted">
        For PCs no tool manages. Download the signed collector, run it on each PC as administrator (USB, share, GPO or RMM), then upload the
        .ccre files here. Each bundle is encrypted for this office only. It reads security settings only: no files, email, browser data or passwords.
      </p>
      {st && !st.enabled && <div className="error">The collector is not enabled for this office yet. A platform administrator creates its key.</div>}
      <div className="row">
        <button onClick={download} disabled={!st?.enabled}>Download collector</button>
        <label>
          Upload .ccre bundles{" "}
          <input type="file" multiple accept=".ccre" disabled={!st?.enabled || busy} onChange={(e) => { upload(e.target.files); e.target.value = ""; }} />
        </label>
        {busy && <span className="muted">Uploading…</span>}
      </div>
      {results.length > 0 && (
        <table style={{ marginTop: "0.75rem" }}>
          <tbody>
            {results.map((r, i) => (
              <tr key={i}><td>{r.name}</td><td><span className={`pill ${r.ok ? "pass" : "fail"}`}>{r.ok ? "Loaded" : "Refused"}</span></td><td>{r.text}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      {error && <div className="error">{error}</div>}
      {showHistory && st && (
        <>
          <h3>Downloads</h3>
          <table>
            <thead><tr><th>Downloaded</th><th>By</th><th>Bundles</th><th></th></tr></thead>
            <tbody>
              {st.downloads.map((d) => (
                <tr key={d.id}>
                  <td>{new Date(d.created_at).toLocaleString()}</td><td>{d.created_by}</td><td>{d.bundles}</td>
                  <td>{d.revoked_at ? <span className="muted">Revoked by {d.revoked_by}</span> : <button className="secondary" onClick={() => revoke(d.id)}>Revoke</button>}</td>
                </tr>
              ))}
              {st.downloads.length === 0 && <tr><td colSpan={4} className="muted">No downloads yet.</td></tr>}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

type Facts = {
  collector?: { finished?: string; elevated?: boolean; version?: string };
  device?: { manufacturer?: string; model?: string; os_version?: string; os_build?: string };
  updates?: { latest_kb?: string; latest_install?: string; count?: number } | null;
  disk?: { bitlocker?: { protection_on?: boolean } | null; secure_boot?: { enabled?: boolean | null }; tpm?: { present?: boolean; version?: string } | null };
  security?: { edr_agents?: { product: string; state: string }[]; defender?: { realtime?: boolean } | null; firewall?: { profile: string; enabled: boolean }[] | null };
  accounts?: { local_admins?: string[] | null; password_policy?: Record<string, string> | null };
  join?: { domain_joined?: boolean | null; domain?: string | null; entra_joined?: boolean | null } | null;
  errors?: string[];
};

const yn = (v: boolean | null | undefined) => (v === true ? "Yes" : v === false ? "No" : "Unknown");

/** What the collector read on one PC, in the words a county engineer uses. */
export function CollectedFacts({ f }: { f: Facts }) {
  const rows: [string, string][] = [
    ["Collected", `${f.collector?.finished ? new Date(f.collector.finished).toLocaleString() : "—"}${f.collector?.elevated ? "" : " (not as administrator)"}`],
    ["Make / model", `${f.device?.manufacturer ?? ""} ${f.device?.model ?? ""}`.trim() || "—"],
    ["Windows", `${f.device?.os_version ?? ""} build ${f.device?.os_build ?? "—"}`],
    ["Latest update", f.updates?.latest_kb ? `${f.updates.latest_kb}, ${f.updates.latest_install ? new Date(f.updates.latest_install).toLocaleDateString() : "date unknown"}` : "—"],
    ["Security agents", (f.security?.edr_agents ?? []).map((a) => `${a.product} (${a.state})`).join(", ") || "None found"],
    ["Defender real-time", yn(f.security?.defender?.realtime)],
    ["Firewall", (f.security?.firewall ?? []).map((p) => `${p.profile} ${p.enabled ? "on" : "OFF"}`).join(", ") || "—"],
    ["BitLocker (system drive)", yn(f.disk?.bitlocker?.protection_on)],
    ["Secure Boot", yn(f.disk?.secure_boot?.enabled)],
    ["TPM", f.disk?.tpm?.present ? `Present${f.disk.tpm.version ? `, ${f.disk.tpm.version}` : ""}` : yn(f.disk?.tpm?.present)],
    ["Local administrators", (f.accounts?.local_admins ?? []).join(", ") || "—"],
    ["Password policy", Object.entries(f.accounts?.password_policy ?? {}).map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`).join("; ") || "—"],
    ["Joined to", [f.join?.domain_joined ? `domain ${f.join.domain ?? ""}` : "", f.join?.entra_joined ? "Microsoft Entra" : ""].filter(Boolean).join(" and ") || "Not joined"],
  ];
  return (
    <table>
      <tbody>
        {rows.map(([k, v]) => <tr key={k}><td style={{ width: "14rem" }} className="muted">{k}</td><td>{v}</td></tr>)}
        {(f.errors ?? []).length > 0 && <tr><td className="muted">Could not read</td><td>{f.errors!.join("; ")}</td></tr>}
      </tbody>
    </table>
  );
}
