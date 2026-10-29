import React, { useState } from "react";
import { SeverityBadge, TagBadge } from "../components/Badges";
import { parsePcapBinary } from "../utils/helpers";

export const NetworkAnalysis = ({
  plant,
  ips,
  netEvents,
  netStats,
  onPcapAnalyzed,
  onUploadPcap,
  t0
}) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileMsg, setFileMsg] = useState("");
  const [isSuccess, setIsSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleFileChange = (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const name = f.name.toLowerCase();
    if (!name.endsWith(".pcap") && !name.endsWith(".pcapng")) {
      setFileMsg("Unsupported file type. Use .pcap or .pcapng.");
      setIsSuccess(false);
      setSelectedFile(null);
    } else if (f.size > 50 * 1048576) {
      setFileMsg(`File is ${(f.size / 1048576).toFixed(1)} MB. The limit is 50 MB.`);
      setIsSuccess(false);
      setSelectedFile(null);
    } else {
      setSelectedFile(f);
      setFileMsg(`${f.name} is ready. Click the Analyze button.`);
      setIsSuccess(true);
    }
  };

  const handleAnalyzePcap = async () => {
    if (!selectedFile) {
      setFileMsg("Choose a capture file first.");
      setIsSuccess(false);
      return;
    }

    setLoading(true);
    setFileMsg(`Uploading and analyzing ${selectedFile.name}...`);
    setIsSuccess(false);

    try {
      if (onUploadPcap) {
        const res = await onUploadPcap(selectedFile);
        setFileMsg(
          `Analysed ${res.packets} packets from ${selectedFile.name}: ${res.findings.length} finding(s) recorded in backend database.`
        );
        setIsSuccess(true);
      } else {
        const buffer = await selectedFile.arrayBuffer();
        const { events, netStats: newStats, packetCount } = parsePcapBinary(buffer, plant.allow, ips, t0);
        onPcapAnalyzed(events, newStats);
        setFileMsg(`Analysed ${packetCount} packets from ${selectedFile.name}: ${events.length} finding(s).`);
        setIsSuccess(true);
      }
    } catch (err) {
      setFileMsg(err.message || "Could not read this capture.");
      setIsSuccess(false);
    } finally {
      setLoading(false);
    }
  };

  const getAssetName = (ip) => {
    const entry = Object.entries(ips).find(([, val]) => val === ip);
    return entry ? entry[0] : "Unmapped";
  };

  const getAssetOf = (ip) => {
    const name = getAssetName(ip);
    return name === "Unmapped" ? <span className="unk">Not in inventory</span> : name;
  };

  const endpoints = netStats
    ? netStats.eps
    : [
        ...Object.entries(ips).map(([a, ip]) => [ip, "Modbus/TCP"]),
        ...netEvents.filter((e) => e.src_ip).map((e) => [e.src_ip, "Modbus/TCP"])
      ];

  const modbusOperations = netStats ? netStats.fc : plant.fc;

  return (
    <div>
      <h1>Network Security Analysis</h1>
      <p className="sub">
        Captures are read offline in a resource-limited worker. The tool never sends packets or touches a live network.
      </p>

      {/* PCAP Drop / Input */}
      <div className="drop">
        Drop a .pcap or .pcapng file here (max 50 MB)
        <br />
        <input
          type="file"
          id="f2"
          accept=".pcap,.pcapng"
          aria-label="PCAP file"
          disabled={loading}
          onChange={handleFileChange}
        />{" "}
        <button className="btn" id="a2" disabled={loading} onClick={handleAnalyzePcap}>
          {loading ? "Analyzing..." : "Analyze capture"}
        </button>
      </div>

      <div className="err" id="e2" style={{ color: isSuccess ? "var(--ok)" : "" }}>
        {fileMsg}
      </div>

      {/* 2-Column Grid */}
      <div className="grid g2" style={{ marginTop: "16px" }}>
        <div className="card">
          <h2>
            Endpoints and protocols <TagBadge kind={netStats ? "obs" : "sim"} />
          </h2>
          <p className="hint">Hosts seen in the capture, matched to the asset inventory. Hosts missing from the inventory are flagged.</p>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Asset</th>
                  <th>Protocols</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.map(([ip, proto]) => (
                  <tr key={ip}>
                    <td className="mono">{ip}</td>
                    <td>{getAssetOf(ip)}</td>
                    <td>{proto}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h2 style={{ marginTop: "16px" }}>Modbus operations seen</h2>
          <p className="hint">
            Function codes counted from request packets. Write codes (5, 6, 15, 16) are checked against the plant allow-list.
          </p>
          <span className="mono">{modbusOperations}</span>
        </div>

        <div className="card">
          <h2>Rule-based findings</h2>
          <p className="hint">
            Each finding names the rule that fired and the packet evidence. A rule match is a lead to verify, not proof of an attack.
          </p>
          {netEvents.length ? (
            netEvents.map((e, idx) => (
              <div key={idx} style={{ padding: "10px 0", borderBottom: "1px solid var(--line)" }}>
                <SeverityBadge sev={e.sev} /> <TagBadge kind={e.kind} /> <b>{e.title}</b>
                <div className="sub" style={{ margin: "6px 0 4px" }}>
                  Why flagged: {e.rule}
                </div>
                <div className="mono" style={{ color: "var(--cy)" }}>
                  {e.ev}
                </div>
              </div>
            ))
          ) : (
            <div className="empty">No network events recorded yet. Upload a PCAP to analyze traffic.</div>
          )}
        </div>
      </div>
    </div>
  );
};
