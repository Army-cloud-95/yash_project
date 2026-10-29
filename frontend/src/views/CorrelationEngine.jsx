import React from "react";
import { TagBadge } from "../components/Badges";
import { formatTime } from "../utils/helpers";

export const CorrelationEngine = ({
  plant,
  netEvents,
  plcEvents,
  telemetry,
  telemetryKind,
  thresholds,
  windowSeconds,
  onWindowChange,
  notes,
  onNotesChange,
  confirmed,
  onToggleConfirmed,
  t0
}) => {
  const pv = plant.pv;
  const deviations = telemetry.filter((r) => !r.miss && (r.p > thresholds.hi || r.p < thresholds.lo));
  const d0 = deviations[0];

  const allEvents = [
    ...netEvents.filter((e) => e.asset === "PLC-01").map((e) => ({ ...e, src: "Network", k: "obs" })),
    ...plcEvents.map((e) => ({ ...e, src: "PLC audit", k: "obs" }))
  ];

  if (d0) {
    allEvents.push({
      t: d0.t,
      asset: "PLC-01",
      title: `${pv.n} ${d0.p} ${pv.u} is outside ${thresholds.lo}–${thresholds.hi}`,
      ev: "Telemetry row at " + formatTime(d0.t, t0),
      src: "Telemetry",
      k: telemetryKind
    });
  }

  allEvents.sort((a, b) => a.t - b.t);

  const near = d0 ? allEvents.filter((e) => e.src !== "Telemetry" && Math.abs(d0.t - e.t) <= windowSeconds) : [];

  return (
    <div>
      <h1>Correlation Engine</h1>
      <p className="sub">Events share one timestamp format and an asset ID. Matching is by time window and asset only.</p>

      {/* Investigation Timeline */}
      <div className="card">
        <h2>Investigation timeline</h2>
        <p className="hint">
          Network, PLC audit and telemetry events on one clock and tied to an asset. The window sets how close in time events must
          be to be grouped.
        </p>
        <div className="row2">
          <label>
            Window ±<span className="mono" id="wv">{windowSeconds}</span> s{" "}
            <input
              type="range"
              id="win"
              min="10"
              max="600"
              step="10"
              value={windowSeconds}
              onChange={(e) => onWindowChange(+e.target.value)}
            />
          </label>
          <span className="badge">Rule: same asset, within window</span>
        </div>

        <div className="tl">
          {allEvents.map((e, idx) => {
            const isMid = near.includes(e);
            const isInf = e.src === "Telemetry";
            const className = `ev ${isMid ? "mid" : isInf ? "inf" : ""}`;
            return (
              <div key={idx} className={className}>
                <span className="mono">{formatTime(e.t, t0)}</span> · {e.src} · <b>{e.asset}</b> <TagBadge kind={e.k} />
                <div>{e.title}</div>
                <div className="mono" style={{ color: "var(--mut)" }}>
                  {e.ev}
                </div>
              </div>
            );
          })}
        </div>

        <div className="note" style={{ marginTop: "12px" }}>
          {near.length ? (
            `${near.length} event(s) fall within ±${windowSeconds} s of the first process deviation (highlighted). This is timing only. Both could share a cause, or be unrelated. Confidence: low to moderate.`
          ) : (
            "No events fall inside this window. Widen it to look for related activity."
          )}
        </div>
      </div>

      {/* Analyst Notes */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>Analyst notes</h2>
        <p className="hint">Record what you verified and what is still open. Marking the finding confirmed changes its evidence label.</p>
        <textarea
          id="notes"
          rows={3}
          style={{ width: "100%", background: "#0c1528", color: "var(--tx)", border: "1px solid var(--line)", borderRadius: "8px", padding: "10px", font: "inherit" }}
          placeholder="Write what you verified, and what is still open"
          value={notes}
          onChange={(e) => onNotesChange(e.target.value)}
        />
        <div className="row2" style={{ marginTop: "10px" }}>
          <button className="btn" id="conf" onClick={onToggleConfirmed}>
            {confirmed ? "Confirmed by analyst" : "Mark finding as confirmed"}
          </button>
        </div>
      </div>
    </div>
  );
};

