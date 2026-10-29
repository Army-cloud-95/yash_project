import React from "react";
import { TagBadge } from "../components/Badges";
import { VALIDATION_DATA } from "../data/initialData";

export const ValidationSecurity = () => {
  const n = VALIDATION_DATA.network;
  const formatPercent = (x) => (x == null ? "n/a" : (x * 100).toFixed(0) + "%");

  const securityModelRows = [
    [
      "Password storage",
      "Demo accounts kept in the page",
      "scrypt hashes with a random salt per user",
      <TagBadge key="1" kind="conf" />
    ],
    [
      "Sessions",
      "Browser session storage",
      "Signed tokens with an expiry. Tampered, expired or wrong-secret tokens are rejected",
      <TagBadge key="2" kind="conf" />
    ],
    [
      "Plant authorization",
      "Hidden in the interface only",
      "Checked in the service layer on every plant-scoped call. Cross-plant access denied on all tested calls",
      <TagBadge key="3" kind="conf" />
    ],
    [
      "Brute-force protection",
      "None",
      "Lockout after 5 failed sign-ins in 15 minutes. Disabled users cannot sign in",
      <TagBadge key="4" kind="conf" />
    ],
    [
      "File uploads",
      "Type and size check",
      "Type, size and content signature checks, sanitized names, random stored names outside the web root",
      <TagBadge key="5" kind="conf" />
    ],
    [
      "Report export",
      "CSV download",
      "Spreadsheet formula characters neutralized",
      <TagBadge key="6" kind="conf" />
    ],
    [
      "HTTP API (FastAPI)",
      "None",
      "Routes written on top of the tested service layer",
      <span key="7" className="tag t-sim">Written, not run here</span>
    ],
    [
      "TLS, SSO and MFA, isolated parsing worker, edge rate limiting",
      "None",
      "Not built",
      <span key="8" className="tag t-inf">Planned</span>
    ]
  ];

  return (
    <div>
      <h1>Validation & Security</h1>
      <p className="sub">
        What the backend does differently from this browser prototype, and what the automated tests and generated scenarios measured.
      </p>

      {/* Security Model Card */}
      <div className="card">
        <h2>Security model</h2>
        <p className="hint">
          This web page holds demo accounts in the browser. The backend folder implements the controls below. The service-layer
          tests ran and passed (33 tests).
        </p>
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Control</th>
                <th>This web prototype</th>
                <th>Backend</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {securityModelRows.map((r, idx) => (
                <tr key={idx}>
                  <td>{r[0]}</td>
                  <td>{r[1]}</td>
                  <td>{r[2]}</td>
                  <td>{r[3]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Network Detection Rules */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>Network detection rules</h2>
        <p className="hint">
          {VALIDATION_DATA.scenarios_per_kind} generated captures for each of{" "}
          {Object.keys(VALIDATION_DATA.scenario_pass_rate_pct).length} scenario kinds, including awkward cases such as truncated
          files, VLAN tags, retransmissions and writes on the wrong port. Crashes: {VALIDATION_DATA.crashes}.
        </p>
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>True positive</th>
                <th>False positive</th>
                <th>False negative</th>
                <th>True negative</th>
                <th>Precision</th>
                <th>Recall</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(n).map(([k, c]) => (
                <tr key={k}>
                  <td>{k}</td>
                  <td>{c.tp}</td>
                  <td>{c.fp}</td>
                  <td>{c.fn}</td>
                  <td>{c.tn}</td>
                  <td>{formatPercent(c.precision)}</td>
                  <td>{formatPercent(c.recall)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="note" style={{ marginTop: "12px" }}>
          These rules are deterministic, so these results show the code follows its rules and copes with odd input. They do not
          measure accuracy on real plant traffic. That needs real captures with known outcomes.
        </div>
      </div>

      {/* Process Limit & Correlation Analysis Grid */}
      <div className="grid g2" style={{ marginTop: "16px" }}>
        <div className="card">
          <h2>Process limit detection</h2>
          <p className="hint">Excursions of different sizes added to normal readings, checked against fixed limits. Normal noise 0.1 bar.</p>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Peak above normal (bar)</th>
                  <th>Series that exceed the limit</th>
                  <th>Detected</th>
                </tr>
              </thead>
              <tbody>
                {VALIDATION_DATA.telemetry_detection.map((x, idx) => (
                  <tr key={idx}>
                    <td>{x.peak_above_baseline}</td>
                    <td>{x.series_exceeding_limit}%</td>
                    <td>{x.detected}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h2 style={{ marginTop: "16px", fontSize: "14px" }}>False alarms on normal readings</h2>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Normal noise (bar)</th>
                  <th>Series with a false alarm</th>
                </tr>
              </thead>
              <tbody>
                {VALIDATION_DATA.telemetry_false_alarms.map((x, idx) => (
                  <tr key={idx}>
                    <td>{x.noise_sd}</td>
                    <td>{x.false_alarm_series_pct}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="hint" style={{ marginTop: "8px" }}>
            Fixed limits only work when they sit well outside normal noise. At 0.5 bar of noise, most normal series raise an
            alarm. Set limits from the real noise level, or move to an adaptive baseline.
          </p>
        </div>

        <div className="card">
          <h2>Correlation window</h2>
          <p className="hint">
            A planted chain (network write, then controller change, then process deviation) hidden among unrelated events on the
            same asset.
          </p>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Window</th>
                  <th>Planted chain found</th>
                  <th>Linked events that are true</th>
                  <th>Unrelated cases still linked</th>
                </tr>
              </thead>
              <tbody>
                {VALIDATION_DATA.correlation.map((x, idx) => (
                  <tr key={idx}>
                    <td>{x.window_s} s</td>
                    <td>{x.planted_chain_found_pct}%</td>
                    <td>{x.linked_events_that_are_true_pct == null ? "n/a" : x.linked_events_that_are_true_pct + "%"}</td>
                    <td>{x.unrelated_scenarios_linked_pct}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="hint" style={{ marginTop: "8px" }}>
            A wider window finds the real chain but also links unrelated events. Even at 120 s, about one in three unrelated cases
            is linked. A link is a lead to check, not proof of cause.
          </p>
        </div>
      </div>

      {/* Next Steps */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>Next validation steps</h2>
        <ul style={{ margin: 0, paddingLeft: "18px", lineHeight: "1.9" }}>
          <li>Run the rules on real captures from a test bench with known events.</li>
          <li>Replace fixed limits with a baseline learned per plant, then re-measure false alarms.</li>
          <li>Run the FastAPI test client against the routes and add them to the same suite.</li>
        </ul>
      </div>
    </div>
  );
};

