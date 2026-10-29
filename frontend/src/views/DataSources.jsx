import React from "react";

export const DataSources = () => {
  const statusWorking = <span className="tag t-conf">Working in preview</span>;
  const statusSimulation = <span className="tag t-sim">Simulation</span>;
  const statusPlanned = <span className="tag t-inf">Planned, needs backend</span>;
  const statusBlocked = <span className="tag t-obs">Blocked by design</span>;

  const dataPathSteps = [
    ["PLCs and RTUs", "OT network"],
    ["SPAN port or TAP", "Passive mirror of traffic"],
    ["Collector", "Read-only capture"],
    ["Parsers", "PCAP, CSV, PDF workers"],
    ["Database", "SQLite, then PostgreSQL"],
    ["API and dashboard", "This interface"]
  ];

  const sourceStatusRows = [
    ["PCAP files", "Offline parse of a saved capture", statusWorking],
    ["Telemetry CSV", "Upload from a historian export", statusWorking],
    ["PDF datasheets", "Text extraction and review", statusWorking],
    ["Live process feed", "Values generated in this page", statusSimulation],
    ["PLC and HMI connections", "Connector setup, status, live tags and events", statusSimulation],
    ["Live packet stream", "Passive TAP or SPAN ingestion", statusPlanned],
    ["OPC UA subscription", "Read-only monitored items", statusPlanned],
    ["Writes or config changes to PLCs", "Not supported", statusBlocked]
  ];

  return (
    <div>
      <h1>Data Sources</h1>
      <p className="sub">
        Live collection is passive and read-only. The platform never sends commands to a controller or scans a production network.
      </p>

      {/* Flow Diagram */}
      <div className="card">
        <h2>Production data path</h2>
        <p className="hint">How data would reach the platform in a real deployment. Every step is passive and read-only.</p>
        <div className="flow">
          {dataPathSteps.map(([title, desc], idx) => (
            <React.Fragment key={idx}>
              <div className="card">
                <b>{title}</b>
                <div style={{ color: "var(--mut)" }}>{desc}</div>
              </div>
              {idx < dataPathSteps.length - 1 && <span className="ar">→</span>}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Source Status Table */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>Source status</h2>
        <p className="hint">What works today, what is simulated, and what needs the backend.</p>
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Method</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {sourceStatusRows.map(([source, method, status], idx) => (
                <tr key={idx}>
                  <td>{source}</td>
                  <td>{method}</td>
                  <td>{status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

