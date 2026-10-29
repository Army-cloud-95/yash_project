import React from "react";
import { SeverityBadge, TagBadge } from "../components/Badges";
import { LiveFeedChart, ParameterTrendChart } from "../components/Charts";

export const PlantOverview = ({
  plant,
  assets,
  findings,
  netEvents,
  telemetry,
  telemetryKind,
  thresholds,
  confirmed,
  liveBuffer,
  liveOn,
  onToggleLive,
  onSimulateExcursion,
  t0
}) => {
  const pv = plant.pv;
  const countSev = (s) => findings.filter((x) => x.sev === s).length;
  const mx = Math.max(1, countSev("high"), countSev("medium"), countSev("low"), countSev("critical"));
  const deviations = telemetry.filter((r) => !r.miss && (r.p > thresholds.hi || r.p < thresholds.lo));
  const missingCount = telemetry.filter((r) => r.miss).length;

  return (
    <div>
      <h1>Overview</h1>
      <p className="sub">Calculated from the stored plant data. The live feed is a simulation and is not read from a controller.</p>

      {/* KPI Cards */}
      <div className="grid g4">
        <div className="card kpi">
          <span>Inventoried assets</span>
          <b>{assets.length}</b>
          <span>{assets.filter((a) => !a.ver).length} need review</span>
        </div>
        <div className="card kpi">
          <span>Open findings</span>
          <b>{findings.length}</b>
          <span>
            {countSev("high")} high, {countSev("medium")} medium
          </span>
        </div>
        <div className="card kpi">
          <span>Network events</span>
          <b>{netEvents.length}</b>
          <span>from 1 capture</span>
        </div>
        <div className="card kpi">
          <span>Process anomalies</span>
          <b>{deviations.length}</b>
          <span>samples out of range</span>
        </div>
        <div className="card kpi">
          <span>Investigations</span>
          <b>1</b>
          <span>{confirmed ? "confirmed by analyst" : "awaiting review"}</span>
        </div>
      </div>

      {/* Live Feed Card */}
      <div className="card" style={{ marginTop: "16px" }}>
        <div className="row2">
          <h2 style={{ margin: 0 }}>
            Live feed: {pv.n} <TagBadge kind="sim" />
          </h2>
          <span className="sp" />
          <button className="btn ghost" id="li" onClick={onSimulateExcursion}>
            Simulate excursion
          </button>
          <button className="btn ghost" id="lp" onClick={onToggleLive}>
            {liveOn ? "Pause" : "Resume"}
          </button>
        </div>
        <p className="hint">
          A rolling 60-second view of the plant's primary parameter with the configured limits. Values are simulated.
        </p>
        <div id="live">
          <LiveFeedChart buf={liveBuffer} plant={plant} thr={thresholds} pv={pv} />
        </div>
      </div>

      {/* Trend & Findings Breakdown */}
      <div className="grid g2" style={{ marginTop: "16px" }}>
        <div className="card">
          <h2>
            {pv.n}, PLC-01 ({pv.u}) <TagBadge kind={telemetryKind} />
          </h2>
          <p className="hint">
            The plant's primary measured parameter over the loaded period. The red line marks the first reading outside the limits.
          </p>
          <ParameterTrendChart tel={telemetry} thr={thresholds} plant={plant} pv={pv} t0={t0} width={640} height={220} />
        </div>

        <div className="card">
          <h2>Findings by severity</h2>
          <p className="hint">Open findings for this plant, grouped by how urgently each needs verification.</p>
          {["critical", "high", "medium", "low"].map((s) => {
            const count = countSev(s);
            const colorVar = s === "critical" ? "crit" : s === "medium" ? "med" : s;
            return (
              <div key={s} className="row2" style={{ margin: "6px 0" }}>
                <span style={{ width: "64px" }}>
                  <SeverityBadge sev={s} />
                </span>
                <div style={{ flex: 1, background: "#0c1528", borderRadius: "6px", height: "10px" }}>
                  <div
                    style={{
                      width: `${(count / mx) * 100}%`,
                      height: "10px",
                      borderRadius: "6px",
                      background: `var(--${colorVar})`
                    }}
                  />
                </div>
                <span className="mono">{count}</span>
              </div>
            );
          })}

          <h2 style={{ marginTop: "20px" }}>Recent activity</h2>
          <p className="hint">Latest imports and checks recorded for this plant.</p>
          <div className="mono" style={{ color: "var(--mut)", lineHeight: "1.9" }}>
            simulation dataset loaded
            <br />
            asset import: s7-1500-datasheet.pdf
            <br />
            pcap analysed: plant-a-sample.pcap
            <br />
            telemetry validated: {telemetry.length} rows, {missingCount} missing
          </div>
        </div>
      </div>
    </div>
  );
};

