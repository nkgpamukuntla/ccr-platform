import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";

type Entry = { at: string; actor_email: string; action: string; detail: Record<string, unknown> };

export default function Audit() {
  const { officeId = "" } = useParams();
  const [rows, setRows] = useState<Entry[] | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api<Entry[]>(`/api/offices/${officeId}/audit`).then(setRows).catch((e) => setError(e.message));
  }, [officeId]);
  return (
    <>
      <h1>Audit log</h1>
      <p className="lead">Append-only. <Link to="/offices">Back to offices</Link></p>
      {error && <div className="error">{error}</div>}
      <table>
        <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Detail</th></tr></thead>
        <tbody>
          {rows?.map((r, i) => (
            <tr key={i}>
              <td>{new Date(r.at).toLocaleString()}</td>
              <td>{r.actor_email}</td>
              <td><code>{r.action}</code></td>
              <td className="muted">{Object.entries(r.detail).map(([k, v]) => `${k}: ${String(v)}`).join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
