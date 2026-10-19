import { useEffect, useState } from "react";
import { api } from "../api";

type Summary = {
  totals: { offices: number; live: number; sites_in_register: number; sites_covered: number };
  by_profile: { profile: string; offices: number }[];
};

export default function Aoc() {
  const [s, setS] = useState<Summary | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api<Summary>("/api/aoc/summary").then(setS).catch((e) => setError(e.message));
  }, []);
  if (error) return <div className="error">{error}</div>;
  if (!s) return <div className="muted">Loading…</div>;
  return (
    <>
      <h1>AOC view</h1>
      <p className="lead">Aggregate across offices. Each county sees only itself.</p>
      <table>
        <tbody>
          <tr><th>Offices onboarding</th><td>{s.totals.offices}</td></tr>
          <tr><th>Live</th><td>{s.totals.live}</td></tr>
          <tr><th>Sites covered</th><td>{s.totals.sites_covered} of {s.totals.sites_in_register} in the register</td></tr>
        </tbody>
      </table>
      <h2>Offices by profile</h2>
      <table>
        <thead><tr><th>Profile</th><th>Offices</th></tr></thead>
        <tbody>
          {s.by_profile.map((p) => (
            <tr key={p.profile}><td>{p.profile === "-" ? "Not profiled yet" : `Profile ${p.profile}`}</td><td>{p.offices}</td></tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
