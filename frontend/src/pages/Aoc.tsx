import { useMe } from "../App";
import { WorkspaceSummary } from "./Workspaces";

/** The AOC view: the courts workspace's aggregate. Each county sees only itself. */
export default function Aoc() {
  const me = useMe();
  const courts = me.viewer_workspaces.find((w) => w.kind === "courts");
  return (
    <>
      <h1>AOC view</h1>
      <p className="lead">Aggregate across the court offices. Each county sees only itself.</p>
      {courts ? <WorkspaceSummary id={courts.id} /> : <div className="error">AOC view only.</div>}
    </>
  );
}
