export default function Planned({ area, phase, what }: { area: string; phase: string; what: string }) {
  return (
    <>
      <h1>{area}</h1>
      <div className="card">
        <p>{what}</p>
        <p className="muted">Arrives in build phase {phase}.</p>
      </div>
    </>
  );
}
