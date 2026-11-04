import { createContext, ReactNode, useContext, useEffect, useState } from "react";
import { matchPath, NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, Me, OfficeRow } from "./api";
import Offices from "./pages/Offices";
import Wizard from "./pages/Wizard";
import Aoc from "./pages/Aoc";
import Audit from "./pages/Audit";
import Posture, { PosturePicker } from "./pages/Posture";
import OfficeMembers, { Users } from "./pages/Members";
import Findings, { FindingsPicker } from "./pages/Findings";
import Devices from "./pages/Devices";
import Workspaces from "./pages/Workspaces";
import Remediation, { RemediationPicker } from "./pages/Remediation";
import Evidence, { EvidencePicker } from "./pages/Evidence";
import Compliance, { CompliancePicker } from "./pages/Compliance";

const MeContext = createContext<Me | null>(null);
export const useMe = () => useContext(MeContext)!;

// The office being looked at, kept while moving between sections (and across visits, per browser).
const OfficeContext = createContext<string>("");
const KEY = "ccr.office";
const remember = (id: string) => {
  try {
    localStorage.setItem(KEY, id);
  } catch {
    /* storage unavailable: the choice lasts for this visit only */
  }
};
const recall = () => {
  try {
    return localStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
};

// Each section has a picker (no office chosen yet) and an office page.
const SECTIONS = [
  ["posture", "Posture", "Where you stand on the eight controls"],
  ["devices", "Devices", "Every computer and its protection"],
  ["findings", "Findings", "Every check we ran and its result"],
  ["remediation", "Action plan", "What to do, who owns it, by when"],
  ["evidence", "Evidence", "The answers to hand to a court or insurer"],
  ["compliance", "Compliance", "Each country's rules, matched to what we checked"],
] as const;

function OfficeSwitcher({ offices, current, onPick }: { offices: OfficeRow[]; current: string; onPick: (id: string) => void }) {
  if (offices.length === 0) return null;
  return (
    <div className="switcher">
      <label htmlFor="office-pick">Office</label>
      <select id="office-pick" value={current} onChange={(e) => onPick(e.target.value)}>
        {!current && <option value="">Choose an office…</option>}
        {offices.map((o) => (
          <option key={o.id} value={o.id}>{o.name}</option>
        ))}
      </select>
    </div>
  );
}

/** A section's index: go straight to the chosen office, else show the picker. */
function Section({ name, picker }: { name: string; picker: ReactNode }) {
  const office = useContext(OfficeContext);
  return office ? <Navigate to={`/offices/${office}/${name}`} replace /> : <>{picker}</>;
}

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [offices, setOffices] = useState<OfficeRow[]>([]);
  const [office, setOffice] = useState(recall());
  const [error, setError] = useState("");
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    api<Me>("/api/me").then(setMe).catch((e) => setError(String(e.message)));
    api<OfficeRow[]>("/api/offices").then(setOffices).catch(() => setOffices([]));
  }, []);

  // Opening any office page selects that office.
  const inPath = matchPath("/offices/:officeId/*", location.pathname)?.params.officeId ?? "";
  useEffect(() => {
    if (inPath && inPath !== office) {
      setOffice(inPath);
      remember(inPath);
    }
  }, [inPath]);

  // Forget a remembered office this user can no longer see; with only one office, choose it.
  useEffect(() => {
    if (offices.length === 0) return;
    if (office && !offices.some((o) => o.id === office)) {
      setOffice("");
      remember("");
    } else if (!office && offices.length === 1) {
      setOffice(offices[0].id);
      remember(offices[0].id);
    }
  }, [offices]);

  const pick = (id: string) => {
    setOffice(id);
    remember(id);
    const here = SECTIONS.find(([s]) => location.pathname.endsWith(`/${s}`) || location.pathname === `/${s}`);
    navigate(`/offices/${id}/${here ? here[0] : "posture"}`);
  };

  if (error) return <div className="center">Could not load your session: {error}</div>;
  if (!me) return <div className="center">Loading…</div>;

  return (
    <MeContext.Provider value={me}>
      <OfficeContext.Provider value={office}>
        <div className="shell">
          <aside className="nav">
            <div className="brand">CCR</div>
            <OfficeSwitcher offices={offices} current={office} onPick={pick} />
            <NavLink to="/offices" end>Onboarding</NavLink>
            {SECTIONS.map(([s, label, hint]) => (
              <NavLink key={s} to={office ? `/offices/${office}/${s}` : `/${s}`} title={hint}>
                {label}
              </NavLink>
            ))}
            {me.viewer_workspaces.some((w) => w.kind === "courts") && <NavLink to="/aoc">AOC view</NavLink>}
            {(me.is_admin || me.viewer_workspaces.length > 0) && <NavLink to="/workspaces">Workspaces</NavLink>}
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
              <Route path="/workspaces" element={<Workspaces />} />
              <Route path="/workspaces/:workspaceId" element={<Workspaces />} />
              <Route path="/users" element={<Users />} />
              <Route path="/offices/:officeId/members" element={<OfficeMembers />} />
              <Route path="/posture" element={<Section name="posture" picker={<PosturePicker />} />} />
              <Route path="/offices/:officeId/posture" element={<Posture />} />
              <Route path="/devices" element={<Section name="devices" picker={<PosturePicker />} />} />
              <Route path="/offices/:officeId/devices" element={<Devices />} />
              <Route path="/findings" element={<Section name="findings" picker={<FindingsPicker />} />} />
              <Route path="/offices/:officeId/findings" element={<Findings />} />
              <Route path="/remediation" element={<Section name="remediation" picker={<RemediationPicker />} />} />
              <Route path="/offices/:officeId/remediation" element={<Remediation />} />
              <Route path="/evidence" element={<Section name="evidence" picker={<EvidencePicker />} />} />
              <Route path="/offices/:officeId/evidence" element={<Evidence />} />
              <Route path="/compliance" element={<Section name="compliance" picker={<CompliancePicker />} />} />
              <Route path="/offices/:officeId/compliance" element={<Compliance />} />
              <Route path="*" element={<Navigate to="/offices" replace />} />
            </Routes>
          </main>
        </div>
      </OfficeContext.Provider>
    </MeContext.Provider>
  );
}
