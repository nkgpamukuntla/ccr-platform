import { createContext, useContext, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { api, Me } from "./api";
import Offices from "./pages/Offices";
import Wizard from "./pages/Wizard";
import Aoc from "./pages/Aoc";
import Audit from "./pages/Audit";
import Planned from "./pages/Planned";
import Posture, { PosturePicker } from "./pages/Posture";
import OfficeMembers, { Users } from "./pages/Members";
import Findings, { FindingsPicker } from "./pages/Findings";
import Devices from "./pages/Devices";

const MeContext = createContext<Me | null>(null);
export const useMe = () => useContext(MeContext)!;

// Navigation from the walkthrough (slide 15). Later-phase areas show what they will hold.
const NAV = [
  ["/offices", "Onboarding"],
  ["/posture", "Posture"],
  ["/findings", "Findings"],
  ["/remediation", "Remediation"],
  ["/evidence", "Evidence"],
] as const;

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<Me>("/api/me").then(setMe).catch((e) => setError(String(e.message)));
  }, []);

  if (error) return <div className="center">Could not load your session: {error}</div>;
  if (!me) return <div className="center">Loading…</div>;

  return (
    <MeContext.Provider value={me}>
      <div className="shell">
        <aside className="nav">
          <div className="brand">CCR</div>
          {NAV.map(([to, label]) => (
            <NavLink key={to} to={to}>
              {label}
            </NavLink>
          ))}
          {me.is_aoc && <NavLink to="/aoc">AOC view</NavLink>}
          {me.is_admin && <NavLink to="/users">Users</NavLink>}
          <div className="nav-foot">
            <div className="who">{me.email}</div>
            <div className="env">{me.environment}</div>
            <a href="/auth/logout">Sign out</a>
          </div>
        </aside>
        <main className="content">
          <Routes>
            <Route path="/" element={<Navigate to="/offices" replace />} />
            <Route path="/offices" element={<Offices />} />
            <Route path="/offices/:officeId/onboarding/:step" element={<Wizard />} />
            <Route path="/offices/:officeId/audit" element={<Audit />} />
            <Route path="/aoc" element={<Aoc />} />
            <Route path="/users" element={<Users />} />
            <Route path="/offices/:officeId/members" element={<OfficeMembers />} />
            <Route path="/posture" element={<PosturePicker />} />
            <Route path="/offices/:officeId/posture" element={<Posture />} />
            <Route path="/findings" element={<FindingsPicker />} />
            <Route path="/offices/:officeId/findings" element={<Findings />} />
            <Route path="/offices/:officeId/devices" element={<Devices />} />
            <Route path="/remediation" element={<Planned area="Remediation" phase="5" what="Work moves across the board and closes only on fresh evidence." />} />
            <Route path="/evidence" element={<Planned area="Evidence pack" phase="5" what="The same evidence rendered for the insurer or the AOC; the county remains the submitter." />} />
            <Route path="*" element={<Navigate to="/offices" replace />} />
          </Routes>
        </main>
      </div>
    </MeContext.Provider>
  );
}
