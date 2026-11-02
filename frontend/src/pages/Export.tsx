import { useState } from "react";
import { download } from "../api";

/** Excel and CSV buttons for one export of an office. */
export default function Export({ officeId, what, query = "", csv = true }: { officeId: string; what: string; query?: string; csv?: boolean }) {
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const get = async (fmt: string) => {
    setBusy(fmt);
    setError("");
    try {
      await download(`/api/offices/${officeId}/export/${what}.${fmt}${query}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  };
  return (
    <span className="row" style={{ gap: "0.4rem" }}>
      <button className="secondary" disabled={!!busy} onClick={() => get("xlsx")}>{busy === "xlsx" ? "Preparing…" : "Export Excel"}</button>
      {csv && <button className="secondary" disabled={!!busy} onClick={() => get("csv")}>{busy === "csv" ? "Preparing…" : "CSV"}</button>}
      {error && <span className="error">{error}</span>}
    </span>
  );
}
