import React from "react";
import { Sparkline } from "./Sparkline";

export const LandingPage = ({ plants, onGoToLogin }) => {
  const features = [
    ["Live Operations", "Connect PLCs and HMIs read-only and follow live process data, assets and security events."],
    ["Asset management", "One inventory built from datasheets and live discovery, with unverified values clearly marked."],
    ["Network security", "Rule-based detections from industrial traffic, each with the packet evidence behind it."],
    ["Process analytics", "Trends, limits and statistics for the measured parameters of each plant."],
    ["Correlation", "Network, controller audit and process events on one timeline, with honest uncertainty."],
    ["Risk and compliance", "A transparent posture score and a readiness checklist aligned to IEC 62443 themes."]
  ];

  const pricing = [
    ["Starter", "₹9,999", "per plant per month", ["1 plant", "Up to 50 assets", "2 users", "Reports as CSV and PDF"], false],
    ["Professional", "₹24,999", "per plant per month", ["Up to 5 plants", "Up to 200 assets", "10 users", "Live Operations and alerts", "Audit log and API keys"], true],
    ["Enterprise", "Custom", "contact sales", ["Unlimited plants", "Single sign-on", "Dedicated collector support", "Custom retention"], false]
  ];

  const totalAssets = plants.reduce((a, p) => a + p.assets.length, 0);

  const scrollTo = (id) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: "smooth" });
    }
  };

  return (
    <div className="land">
      <div className="lw">
        <div className="lnav">
          <div className="logo">
            <i />
            OT Sentinel
          </div>
          <span className="sp" />
          <button className="btn ghost" id="lf" onClick={() => scrollTo("lfs")}>
            Features
          </button>
          <button className="btn ghost" id="lpr" onClick={() => scrollTo("lprs")}>
            Pricing
          </button>
          <button className="btn" id="lsi" onClick={onGoToLogin}>
            Sign in
          </button>
        </div>

        <div className="hero grid g2" style={{ alignItems: "center" }}>
          <div>
            <h1>One view of your plant's process and security</h1>
            <p>
              OT Sentinel connects to PLCs and HMIs without writing to them, keeps your asset inventory current, flags suspicious
              activity and shows the evidence behind every finding.
            </p>
            <div className="row2">
              <button className="btn" id="lsi2" onClick={onGoToLogin}>
                Sign in
              </button>
              <button className="btn ghost" id="lpr2" onClick={() => scrollTo("lprs")}>
                See pricing
              </button>
            </div>
            <p className="hint" style={{ margin: "14px 0 0" }}>
              Read-only by design. Evidence on every finding. Access limited per plant.
            </p>
          </div>

          <div className="card">
            <div className="row2">
              <b>Fleet overview</b>
              <span className="sp" />
              <span className="sev s-low">Simulation</span>
            </div>
            <Sparkline data={plants[0].tel.map((r) => r.p)} width={400} height={70} />
            <div className="grid g4" style={{ marginTop: "10px", gap: "8px" }}>
              {[
                ["Plants", plants.length],
                ["Assets", totalAssets],
                ["Mode", "Read-only"]
              ].map(([k, v]) => (
                <div key={k} className="card kpi" style={{ padding: "10px" }}>
                  <span>{k}</span>
                  <b style={{ fontSize: "22px" }}>{v}</b>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="lsec" id="lfs">
          <h2>Everything in one platform</h2>
          <p className="sub">Security and process teams work from the same data.</p>
          <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))" }}>
            {features.map(([title, desc]) => (
              <div key={title} className="card">
                <b>{title}</b>
                <p className="hint" style={{ margin: "6px 0 0" }}>
                  {desc}
                </p>
              </div>
            ))}
          </div>
        </div>

        <div className="lsec">
          <h2>How it works</h2>
          <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
            {[
              ["1. Connect", "Mirror traffic from the plant network or read from a PLC or HMI. Writes are blocked."],
              ["2. Analyze", "Assets, process data and network events are checked against rules and limits."],
              ["3. Act", "Review findings with evidence, add them to a report and follow the suggested checks."]
            ].map(([title, desc]) => (
              <div key={title} className="card">
                <b>{title}</b>
                <p className="hint" style={{ margin: "6px 0 0" }}>
                  {desc}
                </p>
              </div>
            ))}
          </div>
        </div>

        <div className="lsec" id="lprs">
          <h2>Pricing</h2>
          <p className="sub">Illustrative pricing for this prototype.</p>
          <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
            {pricing.map(([planName, price, sub, items, isPop]) => (
              <div key={planName} className={`card price ${isPop ? "pop" : ""}`}>
                <b>{planName}</b>
                <b className="pr">{price}</b>
                <span className="hint" style={{ margin: 0 }}>
                  {sub}
                </span>
                <ul>
                  {items.map((x, idx) => (
                    <li key={idx}>{x}</li>
                  ))}
                </ul>
                <button className={`btn ${isPop ? "" : "ghost"}`} data-si onClick={onGoToLogin}>
                  Get started
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className="sub" style={{ padding: "24px 0", borderTop: "1px solid var(--line)", fontSize: "12.5px" }}>
          OT Sentinel prototype. Simulation data is shown throughout.
        </div>
      </div>
    </div>
  );
};

