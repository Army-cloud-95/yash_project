import React, { useState } from "react";
import { SeverityBadge, TagBadge } from "../components/Badges";
import { downloadCsvFile } from "../utils/helpers";

export const ThreatIntelReports = ({ findings, onDownloadServerCsv }) => {
  const [downloading, setDownloading] = useState(false);

  const attackMappings = findings
    .filter((x) => x.rule && x.rule.startsWith("R-MB-03"))
    .flatMap((x) => [
      {
        id: "T0836",
        name: "Modify Parameter",
        from: x.id,
        why: "A write function code to a holding register was observed. Supported by packet evidence."
      },
      {
        id: "T0855",
        name: "Unauthorized Command Message",
        from: x.id,
        why: "Source host is not on the allow-list. Needs analyst check before use."
      }
    ]);

  const handleDownloadCsv = async () => {
    if (onDownloadServerCsv) {
      setDownloading(true);
      try {
        await onDownloadServerCsv();
      } catch (err) {
        // Fallback to client CSV if server request fails
        const esc = (s) => `"${String(s || "").replace(/"/g, '""')}"`;
        const rows = [
          "id,asset,finding,severity,evidence_type,evidence,verification",
          ...findings.map((x) =>
            [x.id, x.asset, x.title, x.sev, x.kind, x.ev, x.verify].map(esc).join(",")
          )
        ];
        downloadCsvFile("ot-sentinel-report.csv", rows.join("\n"));
      } finally {
        setDownloading(false);
      }
    } else {
      const esc = (s) => `"${String(s || "").replace(/"/g, '""')}"`;
      const rows = [
        "id,asset,finding,severity,evidence_type,evidence,verification",
        ...findings.map((x) =>
          [x.id, x.asset, x.title, x.sev, x.kind, x.ev, x.verify].map(esc).join(",")
        )
      ];
      downloadCsvFile("ot-sentinel-report.csv", rows.join("\n"));
    }
  };

  const handlePrint = () => {
    try {
      window.print();
    } catch {
      // ignore
    }
  };

  return (
    <div>
      <h1>Threat Intelligence & Reports</h1>
      <p className="sub">
        Only findings with packet or log evidence are mapped. Mappings are suggestions for analyst review. No external threat feeds
        are queried.
      </p>

      {/* ATT&CK Table */}
      <div className="card">
        <h2>ATT&CK for ICS mapping</h2>
        <p className="hint">Techniques suggested only where packet or log evidence supports them. Each mapping needs analyst review before use.</p>
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Technique</th>
                <th>Finding</th>
                <th>Rationale</th>
              </tr>
            </thead>
            <tbody>
              {attackMappings.length ? (
                attackMappings.map((a, idx) => (
                  <tr key={idx}>
                    <td>
                      <span className="mono">{a.id}</span>
                      <br />
                      {a.name}
                    </td>
                    <td className="mono">{a.from}</td>
                    <td>{a.why}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={3} className="empty">
                    No ATT&CK techniques mapped for the current findings.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Report Contents Table */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>Report contents</h2>
        <p className="hint">What the exported report will contain: asset, finding, severity, evidence type and how to verify it.</p>
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Asset</th>
                <th>Finding</th>
                <th>Severity</th>
                <th>Evidence type</th>
                <th>How to verify</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((x) => (
                <tr key={x.id}>
                  <td className="mono">{x.id}</td>
                  <td>{x.asset}</td>
                  <td>{x.title}</td>
                  <td>
                    <SeverityBadge sev={x.sev} />
                  </td>
                  <td>
                    <TagBadge kind={x.kind} />
                  </td>
                  <td>{x.verify}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="row2" style={{ marginTop: "14px" }}>
          <button className="btn" id="csv" disabled={downloading} onClick={handleDownloadCsv}>
            {downloading ? "Downloading..." : "Download CSV"}
          </button>
          <button className="btn ghost" id="pdf" onClick={handlePrint}>
            Print or save as PDF
          </button>
        </div>
      </div>
    </div>
  );
};
