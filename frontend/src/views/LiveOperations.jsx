import React, { useState } from "react";
import { SeverityBadge, TagBadge } from "../components/Badges";
import { LiveFeedChart } from "../components/Charts";
import { formatTime } from "../utils/helpers";

export const LiveOperations = ({
  plant,
  assets,
  ips,
  connections,
  onToggleConnection,
  onAddConnection,
  liveBuffer,
  liveK,
  liveEvents,
  onAcknowledgeEvent,
  onAddEventToReport,
  onDraftUnlistedAsset,
  onSimulateExcursion,
  thresholds,
  t0
}) => {
  const [activeTab, setActiveTab] = useState("a"); // "a": Live analysis, "s": Asset management, "c": Cybersecurity
  const [addOpen, setAddOpen] = useState(false);
  const [addForm, setAddForm] = useState({
    name: "",
    asset: assets[0]?.id || "PLC-01",
    proto: "Modbus/TCP",
    host: "",
    port: "502",
    mode: "Passive mirror (SPAN/TAP)",
    iv: "1"
  });
  const [formErr, setFormErr] = useState("");

  const pv = plant.pv;
  const connectedCount = connections.filter((c) => c.st === "up").length;

  // Latency calculation
  const upConnections = connections.filter((c) => c.st === "up");
  const avgLatency = upConnections.length
    ? Math.round(upConnections.reduce((a, c) => a + (c.lat || 0), 0) / upConnections.length)
    : 0;

  // Rolling statistics from live buffer (last 60)
  const b = liveBuffer;
  const rollingMean = b.length ? b.reduce((x, y) => x + y, 0) / b.length : 0;
  const rollingVariance = b.length > 1
    ? b.reduce((x, y) => x + (y - rollingMean) ** 2, 0) / (b.length - 1)
    : 0;
  const rollingStdDev = Math.sqrt(rollingVariance);
  const rollingMin = b.length ? Math.min(...b) : 0;
  const rollingMax = b.length ? Math.max(...b) : 0;
  const rollingOutside = b.filter((x) => x > thresholds.hi || x < thresholds.lo).length;

  // Live tags
  const lastVal = b.length ? b[b.length - 1] : 0;
  const scanTime = 11 + 2 * Math.sin(liveK / 4);
  const packetRate = 20 + 4 * Math.sin(liveK / 3);
  const checkTagState = (val, lo, hi) => (val > hi ? "High" : val < lo ? "Low" : "Normal");

  const tagsList = [
    [pv.n, lastVal.toFixed(2), pv.u, `${thresholds.lo} to ${thresholds.hi}`, checkTagState(lastVal, thresholds.lo, thresholds.hi)],
    ["Controller scan time", scanTime.toFixed(1), "ms", "up to 25", checkTagState(scanTime, 0, 25)],
    ["Link latency", String(avgLatency), "ms", "up to 50", checkTagState(avgLatency, 0, 50)],
    ["Packet rate", packetRate.toFixed(0), "pkts/s", "10 to 40", checkTagState(packetRate, 10, 40)],
    ["Motor state", "ON", "", "ON", "Normal"],
    ["Valve state", "OPEN", "", "OPEN", "Normal"]
  ];

  // Live events categorized
  const cyberEvents = liveEvents.filter((x) => x.cat === "Cyber");
  const assetEvents = liveEvents.filter((x) => x.cat === "Asset");
  const processAlerts = liveEvents.filter((x) => x.cat === "Process");
  const unackProcess = processAlerts.filter((y) => !y.ack).length;
  const unackCyber = cyberEvents.filter((y) => !y.ack).length;

  const handleSaveConnection = () => {
    const nm = addForm.name.trim();
    const h = addForm.host.trim();
    const p = +addForm.port;
    const iv = +addForm.iv;

    if (!nm) {
      setFormErr("Enter a name.");
      return;
    }
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h.split(".").some((x) => +x > 255)) {
      setFormErr("Enter a valid IPv4 address.");
      return;
    }
    if (!(p >= 1 && p <= 65535)) {
      setFormErr("Port must be 1 to 65535.");
      return;
    }
    if (!(iv >= 1 && iv <= 60)) {
      setFormErr("Interval must be 1 to 60 seconds.");
      return;
    }

    onAddConnection({
      name: nm,
      asset: addForm.asset,
      proto: addForm.proto,
      host: h,
      port: p,
      mode: addForm.mode,
      iv
    });

    setAddOpen(false);
    setFormErr("");
    setAddForm({
      name: "",
      asset: assets[0]?.id || "PLC-01",
      proto: "Modbus/TCP",
      host: "",
      port: "502",
      mode: "Passive mirror (SPAN/TAP)",
      iv: "1"
    });
  };

  const renderEventList = (list, showActions) => {
    if (!list.length) {
      return <div className="empty">Nothing so far. Monitoring is active.</div>;
    }
    return (
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Severity</th>
              <th>Event</th>
              <th>Asset</th>
              <th>Status</th>
              {showActions && <th></th>}
            </tr>
          </thead>
          <tbody>
            {list.map((x) => (
              <tr key={x.id}>
                <td className="mono">{formatTime(x.t, t0)}</td>
                <td>
                  <SeverityBadge sev={x.sev} />
                </td>
                <td>
                  <b>{x.title}</b>
                  <div style={{ color: "var(--mut)", fontSize: "12.5px" }}>Why flagged: {x.rule}</div>
                  <div className="mono" style={{ color: "var(--cy)" }}>
                    {x.ev}
                  </div>
                </td>
                <td>{x.asset}</td>
                <td>
                  {x.ack ? "Acknowledged" : "Open"}
                  {x.pr ? " · In report" : ""}
                </td>
                {showActions && (
                  <td>
                    {!x.ack && (
                      <button className="btn ghost" style={{ marginRight: "4px" }} onClick={() => onAcknowledgeEvent(x.id)}>
                        Acknowledge
                      </button>
                    )}
                    {!x.pr && (
                      <button className="btn ghost" onClick={() => onAddEventToReport(x)}>
                        Add to report
                      </button>
                    )}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  return (
    <div>
      <h1>Live Operations</h1>
      <p className="sub">
        Connect this plant's PLCs and HMIs, then follow live process data, the device inventory and security events in one place.
        Collection is read-only.
      </p>

      <div className="note" style={{ borderLeftColor: "var(--cy)", marginBottom: "16px" }}>
        Simulation mode. This page opens no network connection. In production, a collector next to the plant network makes the
        connection and streams data here.
      </div>

      <div className="grid g2">
        <div className="card">
          <h2>Connection policy</h2>
          <p className="hint">Applied to every source. It cannot be switched off from the interface.</p>
          <ul style={{ margin: 0, paddingLeft: "18px", lineHeight: "1.9" }}>
            <li>Allowed: Modbus reads (FC 01 to 04), OPC UA browse, read and subscribe.</li>
            <li>Blocked: Modbus writes (FC 05, 06, 15, 16), OPC UA write and method calls.</li>
            <li>Blocked: program download, firmware update and configuration changes.</li>
            <li>No scanning. Only the addresses listed under Sources are contacted.</li>
          </ul>
        </div>

        <div className="card">
          <h2>Add a connection</h2>
          <p className="hint">Credentials, if a source needs them, are held by the collector and never stored in this page.</p>
          {addOpen ? (
            <div>
              <div className="grid g2" style={{ gap: "8px" }}>
                <label>
                  Name
                  <input
                    id="c_name"
                    placeholder="e.g. PLC-01 Modbus"
                    value={addForm.name}
                    onChange={(e) => setAddForm({ ...addForm, name: e.target.value })}
                  />
                </label>
                <label>
                  Asset
                  <select
                    id="c_asset"
                    style={{ width: "100%" }}
                    value={addForm.asset}
                    onChange={(e) => setAddForm({ ...addForm, asset: e.target.value })}
                  >
                    {assets.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.id}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Protocol
                  <select
                    id="c_proto"
                    style={{ width: "100%" }}
                    value={addForm.proto}
                    onChange={(e) => setAddForm({ ...addForm, proto: e.target.value })}
                  >
                    <option>Modbus/TCP</option>
                    <option>OPC UA</option>
                    <option>DNP3</option>
                  </select>
                </label>
                <label>
                  IPv4 address
                  <input
                    id="c_host"
                    value={addForm.host}
                    onChange={(e) => setAddForm({ ...addForm, host: e.target.value })}
                  />
                </label>
                <label>
                  Port
                  <input
                    id="c_port"
                    value={addForm.port}
                    onChange={(e) => setAddForm({ ...addForm, port: e.target.value })}
                  />
                </label>
                <label>
                  Mode
                  <select
                    id="c_mode"
                    style={{ width: "100%" }}
                    value={addForm.mode}
                    onChange={(e) => setAddForm({ ...addForm, mode: e.target.value })}
                  >
                    <option>Passive mirror (SPAN/TAP)</option>
                    <option>Read-only poll</option>
                    <option>Read-only subscription</option>
                  </select>
                </label>
                <label>
                  Interval (seconds)
                  <input
                    id="c_iv"
                    value={addForm.iv}
                    onChange={(e) => setAddForm({ ...addForm, iv: e.target.value })}
                  />
                </label>
              </div>
              <div className="err" id="ce">
                {formErr}
              </div>
              <div className="row2" style={{ marginTop: "8px" }}>
                <button className="btn" id="csv2" onClick={handleSaveConnection}>
                  Save source
                </button>
                <button className="btn ghost" id="ccx" onClick={() => setAddOpen(false)}>
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <button className="btn" id="cadd" onClick={() => setAddOpen(true)}>
              Add connection
            </button>
          )}
        </div>
      </div>

      {/* Sources Table */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>Sources</h2>
        <p className="hint">PLCs and HMIs for this plant. Connect a source to start receiving data.</p>
        <div id="lconn">
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Protocol</th>
                  <th>Endpoint</th>
                  <th>Mode</th>
                  <th>Status</th>
                  <th>Latency</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {connections.length ? (
                  connections.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <b>{c.name}</b>
                        <div className="mono" style={{ color: "var(--mut)" }}>
                          {c.asset}
                        </div>
                      </td>
                      <td>{c.proto}</td>
                      <td className="mono">
                        {c.host}:{c.port}
                      </td>
                      <td>{c.mode}</td>
                      <td>
                        <span className={`sev ${c.st === "up" ? "s-low" : c.st === "connecting" ? "s-medium" : ""}`}>
                          {c.st === "up" ? "Connected" : c.st === "connecting" ? "Connecting" : "Disconnected"}
                        </span>
                      </td>
                      <td className="mono">{c.st === "up" ? `${c.lat} ms` : "—"}</td>
                      <td>
                        <button
                          className={`btn ${c.st === "down" ? "" : "ghost"}`}
                          onClick={() => onToggleConnection(c.id)}
                        >
                          {c.st === "down" ? "Connect" : "Disconnect"}
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="empty">
                      No sources configured. Add a connection to begin.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Live Operations Detail Tabs */}
      <div style={{ marginTop: "16px" }} id="lops">
        {!connectedCount ? (
          <div className="card empty">
            No source is connected. Connect a source above to start live analysis, asset checks and security monitoring.
          </div>
        ) : (
          <>
            <div className="tabs" role="tablist">
              {[
                ["a", "Live analysis", unackProcess],
                ["s", "Asset management", assetEvents.length],
                ["c", "Cybersecurity", unackCyber]
              ].map(([k, n, count]) => (
                <button
                  key={k}
                  className="tab"
                  role="tab"
                  aria-selected={k === activeTab}
                  onClick={() => setActiveTab(k)}
                >
                  {n}
                  {count > 0 && <span className="sev s-medium" style={{ marginLeft: "4px" }}>{count}</span>}
                </button>
              ))}
            </div>

            {/* TAB: Live Analysis */}
            {activeTab === "a" && (
              <div>
                <div className="grid g4">
                  {[
                    ["Rolling mean", "k_m", `${rollingMean.toFixed(2)} ${pv.u}`, "Average of the last 60 samples."],
                    ["Rolling std deviation", "k_s", `${rollingStdDev.toFixed(2)} ${pv.u}`, "Spread of recent readings."],
                    ["Window range", "k_r", `${rollingMin.toFixed(2)} to ${rollingMax.toFixed(2)}`, "Lowest and highest recent reading."],
                    ["Samples outside limits", "k_d", rollingOutside, "Recent readings beyond the plant limits."]
                  ].map(([label, id, val, desc]) => (
                    <div key={label} className="card kpi">
                      <span>{label}</span>
                      <b id={id}>{val}</b>
                      <span style={{ fontSize: "12px" }}>{desc}</span>
                    </div>
                  ))}
                </div>

                <div className="card" style={{ marginTop: "16px" }}>
                  <div className="row2">
                    <h2 style={{ margin: 0 }}>{pv.n}</h2>
                    <span className="sp" />
                    <button className="btn ghost" id="li2" onClick={onSimulateExcursion}>
                      Simulate excursion
                    </button>
                  </div>
                  <p className="hint">Streaming from the connected source at one sample per second, shown against the plant limits.</p>
                  <div id="lchart">
                    <LiveFeedChart buf={liveBuffer} plant={plant} thr={thresholds} pv={pv} showStats={true} />
                  </div>
                </div>

                <div className="card" style={{ marginTop: "16px" }}>
                  <h2>Live tags</h2>
                  <p className="hint">
                    Current value of each monitored tag, including controller and link health, and whether it is inside its limits.
                  </p>
                  <div className="scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Tag</th>
                          <th>Value</th>
                          <th>Unit</th>
                          <th>Limits</th>
                          <th>State</th>
                        </tr>
                      </thead>
                      <tbody>
                        {tagsList.map((t, idx) => (
                          <tr key={idx}>
                            <td>{t[0]}</td>
                            <td className="mono" id={`tv${idx}`}>{t[1]}</td>
                            <td>{t[2]}</td>
                            <td className="mono">{t[3]}</td>
                            <td id={`ts${idx}`}>
                              <span className={`sev s-${t[4] === "Normal" ? "low" : "high"}`}>{t[4]}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="card" style={{ marginTop: "16px" }}>
                  <h2>Process alerts</h2>
                  <p className="hint">Raised when the primary parameter leaves its limits while a source is connected.</p>
                  {renderEventList(processAlerts, false)}
                </div>
              </div>
            )}

            {/* TAB: Asset Management */}
            {activeTab === "s" && (
              <div>
                {(() => {
                  const rows = [
                    ...assets.map((a) => {
                      const c = connections.find((x) => x.asset === a.id);
                      return {
                        id: a.id,
                        nm: a.name,
                        ip: ips[a.id] || "—",
                        link: c ? (c.st === "up" ? "Live" : c.st === "connecting" ? "Connecting" : "Not connected") : "No source configured",
                        inv: a.ver ? "Verified" : "Needs review",
                        un: false
                      };
                    }),
                    ...assetEvents.map((x) => ({
                      id: "Unlisted host",
                      nm: "Seen talking to " + x.asset,
                      ip: x.ip,
                      link: "Seen on network",
                      inv: "Not in inventory",
                      un: true
                    }))
                  ];

                  return (
                    <>
                      <div className="grid g4">
                        {[
                          ["Inventoried assets", assets.length, "Devices recorded for this plant."],
                          ["Reporting live", rows.filter((r) => r.link === "Live").length, "Assets with a connected source."],
                          ["Unlisted devices", assetEvents.length, "Seen on the network, not in inventory."],
                          ["Need review", assets.filter((a) => !a.ver).length, "Inventory values not yet verified."]
                        ].map(([a, v, d]) => (
                          <div key={a} className="card kpi">
                            <span>{a}</span>
                            <b>{v}</b>
                            <span style={{ fontSize: "12px" }}>{d}</span>
                          </div>
                        ))}
                      </div>

                      <div className="card" style={{ marginTop: "16px" }}>
                        <h2>Discovered and inventoried devices</h2>
                        <p className="hint">
                          Compares what the live connection sees with the asset inventory. Unlisted devices can be added to the inventory
                          for review.
                        </p>
                        <div className="scroll">
                          <table>
                            <thead>
                              <tr>
                                <th>Device</th>
                                <th>Address</th>
                                <th>Live link</th>
                                <th>Inventory status</th>
                                <th></th>
                              </tr>
                            </thead>
                            <tbody>
                              {rows.map((r, i) => (
                                <tr key={i}>
                                  <td>
                                    <b>{r.id}</b>
                                    <div style={{ color: "var(--mut)", fontSize: "12.5px" }}>{r.nm}</div>
                                  </td>
                                  <td className="mono">{r.ip}</td>
                                  <td>{r.link}</td>
                                  <td>
                                    {r.un ? (
                                      <span className="sev s-high">Not in inventory</span>
                                    ) : r.inv === "Verified" ? (
                                      <TagBadge kind="verified" />
                                    ) : (
                                      <TagBadge kind="needs_review" />
                                    )}
                                  </td>
                                  <td>
                                    {r.un && (
                                      <button className="btn ghost" onClick={() => onDraftUnlistedAsset(r.ip)}>
                                        Add to inventory
                                      </button>
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </>
                  );
                })()}
              </div>
            )}

            {/* TAB: Cybersecurity */}
            {activeTab === "c" && (
              <div>
                {(() => {
                  const writes = cyberEvents.filter((x) => x.rule.startsWith("R-MB-03")).length;
                  return (
                    <>
                      <div className="grid g4">
                        {[
                          ["High severity open", cyberEvents.filter((x) => x.sev === "high" && !x.ack).length, "Needs verification first."],
                          ["Medium and low open", cyberEvents.filter((x) => x.sev !== "high" && !x.ack).length, "Review when time allows."],
                          ["Writes from other hosts", writes, "Write requests seen from sources outside the allow-list."],
                          ["Writes sent by platform", 0, "Always zero. The platform only reads."]
                        ].map(([a, v, d]) => (
                          <div key={a} className="card kpi">
                            <span>{a}</span>
                            <b>{v}</b>
                            <span style={{ fontSize: "12px" }}>{d}</span>
                          </div>
                        ))}
                      </div>

                      <div className="card" style={{ marginTop: "16px" }}>
                        <h2>Connection posture</h2>
                        <p className="hint">
                          How each source is collected and whether the link is protected. Modbus/TCP and DNP3 carry no encryption of their own.
                        </p>
                        <div className="scroll">
                          <table>
                            <thead>
                              <tr>
                                <th>Source</th>
                                <th>Mode</th>
                                <th>Link protection</th>
                                <th>Platform writes</th>
                                <th>Write allow-list</th>
                              </tr>
                            </thead>
                            <tbody>
                              {connections.map((c) => (
                                <tr key={c.id}>
                                  <td>{c.name}</td>
                                  <td>{c.mode}</td>
                                  <td>
                                    {c.proto === "OPC UA"
                                      ? "Depends on the OPC UA security policy (not checked here)"
                                      : c.proto === "DNP3"
                                      ? "None unless Secure Authentication is used"
                                      : "None, protocol is cleartext"}
                                  </td>
                                  <td>Blocked</td>
                                  <td className="mono">{plant.allow.join(", ")}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>

                      <div className="card" style={{ marginTop: "16px" }}>
                        <h2>Security events</h2>
                        <p className="hint">
                          Rule-based detections from live traffic. Add an event to the report to include it in the findings and ATT&CK mapping.
                          A match is a lead to verify, not proof of an attack.
                        </p>
                        {renderEventList(cyberEvents, true)}
                      </div>
                    </>
                  );
                })()}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

