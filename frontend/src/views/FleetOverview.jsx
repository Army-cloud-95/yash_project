import React from "react";
import { Sparkline } from "../components/Sparkline";
import { TagBadge } from "../components/Badges";

export const FleetOverview = ({
  plants,
  plantSummaries,
  onSelectPlant,
  onNavigate,
  audit,
  users
}) => {
  const getRisk = (r) => {
    if (r >= 5) return ["High", "high"];
    if (r >= 2) return ["Elevated", "medium"];
    return ["Low", "low"];
  };

  const totals = plants.reduce(
    (acc, p, idx) => {
      const s = plantSummaries[idx];
      return {
        as: acc.as + p.assets.length,
        fi: acc.fi + (s?.n || 0),
        hi: acc.hi + (s?.h || 0),
        scoreSum: acc.scoreSum + (s?.score || 0)
      };
    },
    { as: 0, fi: 0, hi: 0, scoreSum: 0 }
  );

  const avgPosture = Math.round(totals.scoreSum / Math.max(1, plants.length));

  // Onboarding steps
  const onboardingSteps = [
    ["Add your plants", true, "f", "Your plants are listed below."],
    ["Inventory your assets", plants.some((p) => p.assets.some((a) => a.ver)), "a", "Import datasheets and verify values."],
    ["Connect a source", audit.some((x) => x.a === "Connect source"), "l", "Connect a PLC or HMI under Live Operations."],
    ["Invite your team", users.some((u) => u.status === "Invited"), "o", "Invite users from Organization."],
    ["Set notification rules", audit.some((x) => x.a === "Change notification rule"), "o", "Choose who is alerted for each severity."]
  ];

  const doneCount = onboardingSteps.filter((x) => x[1]).length;

  return (
    <div>
      <h1>Fleet Overview</h1>
      <p className="sub">All plants in your company. Select a plant to open its dashboard.</p>

      {/* Onboarding card */}
      <div className="card" style={{ marginBottom: "16px" }}>
        <div className="row2" style={{ margin: "0 0 6px" }}>
          <h2 style={{ margin: 0 }}>Get started</h2>
          <span className="sp" />
          <span className="mono">
            {doneCount} of {onboardingSteps.length} done
          </span>
        </div>
        <div style={{ background: "#0c1528", borderRadius: "6px", height: "8px", marginBottom: "10px" }}>
          <div
            style={{
              width: `${(doneCount / onboardingSteps.length) * 100}%`,
              height: "8px",
              borderRadius: "6px",
              background: "var(--cy)"
            }}
          />
        </div>
        {onboardingSteps.map((x, idx) => (
          <div key={idx} className="row2" style={{ margin: "4px 0" }}>
            <span style={{ color: x[1] ? "var(--ok)" : "var(--mut)" }}>{x[1] ? "✔" : "○"}</span>
            <span style={{ flex: 1 }}>
              {x[0]} <span style={{ color: "var(--mut)", fontSize: "12.5px" }}>{x[3]}</span>
            </span>
            {!x[1] && (
              <button className="btn ghost" style={{ padding: "2px 10px" }} onClick={() => onNavigate(x[2])}>
                Go
              </button>
            )}
          </div>
        ))}
      </div>

      {/* KPI Cards */}
      <div className="grid g4">
        {[
          ["Plants", plants.length],
          ["Assets", totals.as],
          ["Open findings", totals.fi],
          ["High severity", totals.hi],
          ["Average posture", avgPosture]
        ].map(([k, v]) => (
          <div key={k} className="card kpi">
            <span>{k}</span>
            <b>{v}</b>
          </div>
        ))}
      </div>

      {/* Plant Cards */}
      <div className="grid g2" style={{ marginTop: "16px" }}>
        {plants.map((p, i) => {
          const s = plantSummaries[i] || { risk: 0, n: 0, h: 0, score: 0 };
          const [riskLabel, riskClass] = getRisk(s.risk);
          return (
            <button key={i} className="card pc" onClick={() => onSelectPlant(i)}>
              <div className="row2" style={{ margin: 0 }}>
                <b>{p.name}</b>
                <span className="sp" />
                <span className={`sev s-${riskClass}`}>{riskLabel} risk</span>
              </div>
              <div className="sub" style={{ margin: "2px 0 10px" }}>
                {p.site} · {p.pv.n} ({p.pv.u})
              </div>
              <Sparkline data={p.tel.map((r) => r.p)} />
              <div className="row2" style={{ margin: "10px 0 0" }}>
                <span className="mono">{p.assets.length} assets</span>
                <span className="mono">{s.n} findings</span>
                <span className="mono">{s.h} high</span>
                <span className="mono">Posture {s.score}</span>
                <span className="sp" />
                <TagBadge kind="sim" />
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
};

