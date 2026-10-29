import React from "react";
import { SeverityBadge } from "../components/Badges";
import { downloadCsvFile } from "../utils/helpers";

export const RiskCompliance = ({
  plant,
  assets,
  findings,
  liveEvents,
  connections,
  thresholds
}) => {
  const pv = plant.pv;
  const countSev = (x) => findings.filter((y) => y.sev === x).length;
  const totalAssets = assets.length || 1;
  const verifiedAssets = assets.filter((a) => a.ver).length;
  const unlistedLive = liveEvents.filter((x) => x.cat === "Asset").length;
  const unreviewedCyber = liveEvents.filter((x) => x.cat === "Cyber" && !x.pr && !x.ack).length;
  const percentVerified = Math.round((verifiedAssets / totalAssets) * 100);
  const cleartextCount = findings.filter((x) => x.rule && x.rule.startsWith("R-PR-01")).length;
  const writeRuleCount = findings.filter((x) => x.rule && x.rule.startsWith("R-MB-03")).length;
  const connectedCount = connections.filter((c) => c.st === "up").length;

  const deductions = [
    [
      "Open findings",
      Math.min(60, countSev("critical") * 20 + countSev("high") * 15 + countSev("medium") * 8 + countSev("low") * 3),
      `${countSev("critical")} critical, ${countSev("high")} high, ${countSev("medium")} medium, ${countSev("low")} low, at 20, 15, 8 and 3 points each (capped at 60)`
    ],
    [
      "Unverified assets",
      Math.round((1 - verifiedAssets / totalAssets) * 15),
      `${verifiedAssets} of ${assets.length} assets verified (up to 15 points)`
    ],
    [
      "Unlisted live devices",
      Math.min(10, unlistedLive * 5),
      `${unlistedLive} seen on the network, 5 points each (capped at 10)`
    ],
    [
      "Unreviewed live security events",
      Math.min(10, unreviewedCyber * 5),
      `${unreviewedCyber} open and not yet in the report, 5 points each (capped at 10)`
    ]
  ];

  const postureScore = Math.max(0, 100 - deductions.reduce((a, x) => a + x[1], 0));

  const checklist = [
    [
      "Asset inventory complete and verified",
      "IEC 62443-2-1 asset management",
      percentVerified >= 90 ? "Pass" : percentVerified >= 50 ? "Partial" : "Gap",
      `${percentVerified}% of assets verified`
    ],
    [
      "Write access limited to an allow-list",
      "IEC 62443-3-3 SR 2.1 authorization enforcement",
      writeRuleCount ? "Gap" : "Pass",
      writeRuleCount ? `${writeRuleCount} write(s) from hosts outside the allow-list` : "No writes from unlisted hosts seen"
    ],
    [
      "Industrial links protected",
      "IEC 62443-3-3 SR 4.1 information confidentiality",
      cleartextCount ? "Partial" : "Pass",
      cleartextCount ? `${cleartextCount} cleartext link(s) seen` : "No cleartext links seen"
    ],
    [
      "Continuous monitoring active",
      "IEC 62443-3-3 SR 6.2 continuous monitoring",
      connectedCount ? "Pass" : "Partial",
      connectedCount ? `${connectedCount} source(s) connected` : "No source connected"
    ],
    [
      "Process limits configured",
      "Operational monitoring",
      thresholds.hi > thresholds.lo ? "Pass" : "Gap",
      `${pv.n} limits ${thresholds.lo} to ${thresholds.hi} ${pv.u}`
    ],
    [
      "Collection is read-only",
      "IEC 62443-3-3 SR 7.7 least functionality",
      "Pass",
      "The platform sends no writes or configuration changes"
    ],
    [
      "Findings carry evidence",
      "IEC 62443-3-3 SR 6.1 audit log accessibility",
      findings.every((x) => x.ev) ? "Pass" : "Partial",
      `${findings.length} finding(s) recorded`
    ]
  ];

  const scoreBadge =
    postureScore >= 80
      ? ["Good", "low", "low"]
      : postureScore >= 60
      ? ["Fair", "medium", "med"]
      : ["Needs attention", "high", "crit"];

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const priorityActions = [...findings].sort((x, y) => sevOrder[x.sev] - sevOrder[y.sev]).slice(0, 5);

  const handleDownloadCsv = () => {
    const q = (x) => `"${String(x).replace(/"/g, '""')}"`;
    const rows = [
      "check,reference,status,basis",
      ...checklist.map((r) => r.map(q).join(",")),
      "",
      `posture_score,${postureScore}`
    ];
    downloadCsvFile("ot-sentinel-readiness.csv", rows.join("\n"));
  };

  return (
    <div>
      <h1>Risk & Compliance</h1>
      <p className="sub">
        One posture score for this plant, how it is calculated, and a readiness checklist aligned to IEC 62443 themes.
      </p>

      {/* Grid: Score and Calculation */}
      <div className="grid g2">
        <div className="card">
          <h2>Posture score</h2>
          <p className="hint">
            Starts at 100 and loses points for open findings, unverified assets and unreviewed live events. Higher is better.
          </p>
          <div className="row2">
            <b className="mono" style={{ fontSize: "44px", lineHeight: 1 }}>
              {postureScore}
            </b>
            <span className={`sev s-${scoreBadge[1]}`}>{scoreBadge[0]}</span>
          </div>
          <div style={{ background: "#0c1528", borderRadius: "6px", height: "10px", marginTop: "8px" }}>
            <div
              style={{
                width: `${postureScore}%`,
                height: "10px",
                borderRadius: "6px",
                background: `var(--${scoreBadge[2]})`
              }}
            />
          </div>
        </div>

        <div className="card">
          <h2>How the score is calculated</h2>
          <p className="hint">Every deduction comes from data on the other pages. Nothing is estimated.</p>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Factor</th>
                  <th>Points lost</th>
                  <th>Basis</th>
                </tr>
              </thead>
              <tbody>
                {deductions.map((x, idx) => (
                  <tr key={idx}>
                    <td>{x[0]}</td>
                    <td className="mono">{x[1]}</td>
                    <td style={{ color: "var(--mut)" }}>{x[2]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Readiness Checklist */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>Readiness checklist</h2>
        <p className="hint">
          Indicators aligned to IEC 62443 themes, calculated from this plant's data. This is not a certification or an audit result.
        </p>
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Check</th>
                <th>Reference</th>
                <th>Status</th>
                <th>Basis</th>
              </tr>
            </thead>
            <tbody>
              {checklist.map((r, idx) => (
                <tr key={idx}>
                  <td>{r[0]}</td>
                  <td style={{ color: "var(--mut)" }}>{r[1]}</td>
                  <td>
                    <span className={`sev s-${r[2] === "Pass" ? "low" : r[2] === "Partial" ? "medium" : "high"}`}>
                      {r[2]}
                    </span>
                  </td>
                  <td>{r[3]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Priority Actions */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>Priority actions</h2>
        <p className="hint">The most severe open findings first, each with the step that would confirm or close it.</p>
        {priorityActions.length ? (
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Asset</th>
                  <th>Finding</th>
                  <th>How to verify</th>
                </tr>
              </thead>
              <tbody>
                {priorityActions.map((x) => (
                  <tr key={x.id}>
                    <td>
                      <SeverityBadge sev={x.sev} />
                    </td>
                    <td>{x.asset}</td>
                    <td>{x.title}</td>
                    <td>{x.verify}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty">No open findings for this plant.</div>
        )}
      </div>

      <div className="row2" style={{ marginTop: "14px" }}>
        <button className="btn" id="rcsv" onClick={handleDownloadCsv}>
          Download checklist CSV
        </button>
      </div>
    </div>
  );
};

