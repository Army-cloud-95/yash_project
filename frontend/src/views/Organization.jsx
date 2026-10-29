import React, { useState } from "react";
import { SeverityBadge } from "../components/Badges";
import { downloadCsvFile } from "../utils/helpers";

export const Organization = ({
  org,
  plants,
  users,
  onToggleUserStatus,
  onInviteUser,
  notificationRules,
  onChangeNotificationRule,
  apiKeys,
  onCreateApiKey,
  onRevokeApiKey,
  auditLog,
  currentUser
}) => {
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("Plant user");
  const [invitePlant, setInvitePlant] = useState(0);
  const [inviteMsg, setInviteMsg] = useState("");

  const totalAssets = plants.reduce((a, p) => a + p.assets.length, 0);

  const handleSendInvite = () => {
    const e = inviteEmail.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)) {
      setInviteMsg("Enter a valid email address.");
      return;
    }
    if (users.some((x) => x.u === e)) {
      setInviteMsg("That user already exists.");
      return;
    }
    if (users.length >= 10) {
      setInviteMsg("User limit reached for this plan.");
      return;
    }

    onInviteUser({
      u: e,
      p: null,
      name: e.split("@")[0],
      role: inviteRole,
      plants: inviteRole === "Company admin" ? [0, 1, 2, 3] : [+invitePlant],
      status: "Invited"
    });

    setInviteEmail("");
    setInviteMsg("");
  };

  const handleDownloadAuditCsv = () => {
    const q = (x) => `"${String(x || "").replace(/"/g, '""')}"`;
    const rows = [
      "time,user,action,detail",
      ...auditLog.map((x) => [x.ts, x.user, x.a, x.d].map(q).join(","))
    ];
    downloadCsvFile("ot-sentinel-audit-log.csv", rows.join("\n"));
  };

  const renderMeter = (label, current, max) => (
    <div style={{ margin: "10px 0" }}>
      <div className="row2" style={{ margin: "0 0 4px" }}>
        <span>{label}</span>
        <span className="sp" />
        <span className="mono">
          {current} of {max}
        </span>
      </div>
      <div style={{ background: "#0c1528", borderRadius: "6px", height: "8px" }}>
        <div
          style={{
            width: `${Math.min(100, (current / max) * 100)}%`,
            height: "8px",
            borderRadius: "6px",
            background: "var(--cy)"
          }}
        />
      </div>
    </div>
  );

  return (
    <div>
      <h1>Organization</h1>
      <p className="sub">Manage the plan, team access, alerts, API keys and audit trail for {org.name}.</p>

      {/* Grid: Plan usage & Notification rules */}
      <div className="grid g2">
        <div className="card">
          <h2>Plan and usage</h2>
          <p className="hint">{org.plan} plan. Limits shown are illustrative.</p>
          {renderMeter("Plants", plants.length, 5)}
          {renderMeter("Assets", totalAssets, 200)}
          {renderMeter("Users", users.length, 10)}
        </div>

        <div className="card">
          <h2>Notification rules</h2>
          <p className="hint">Who is alerted for each severity. Delivery is simulated in this prototype.</p>
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Email</th>
                <th>Slack</th>
              </tr>
            </thead>
            <tbody>
              {Object.keys(notificationRules).map((sev) => (
                <tr key={sev}>
                  <td>
                    <SeverityBadge sev={sev} />
                  </td>
                  {["email", "slack"].map((channel) => (
                    <td key={channel}>
                      <input
                        type="checkbox"
                        checked={!!notificationRules[sev][channel]}
                        aria-label={`${sev} via ${channel}`}
                        onChange={(e) => onChangeNotificationRule(sev, channel, e.target.checked)}
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Team and Access */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>Team and access</h2>
        <p className="hint">Company admins see every plant. Plant users see only their own plant.</p>
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Plant access</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.u}>
                  <td>
                    <b>{u.name}</b>
                    <div className="mono" style={{ color: "var(--mut)" }}>
                      {u.u}
                    </div>
                  </td>
                  <td>{u.role}</td>
                  <td>{u.plants.length === 4 ? "All plants" : plants[u.plants[0]]?.name || "None"}</td>
                  <td>{u.status}</td>
                  <td>
                    {u.u !== currentUser.u && (
                      <button className="btn ghost" onClick={() => onToggleUserStatus(u.u)}>
                        {u.status === "Disabled" ? "Enable" : "Disable"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <h2 style={{ marginTop: "18px", fontSize: "14px" }}>Invite a user</h2>
        <div className="row2">
          <input
            id="inv_e"
            placeholder="name@company.com"
            aria-label="Email"
            value={inviteEmail}
            onChange={(e) => {
              setInviteEmail(e.target.value);
              setInviteMsg("");
            }}
          />
          <select id="inv_r" aria-label="Role" value={inviteRole} onChange={(e) => setInviteRole(e.target.value)}>
            <option>Plant user</option>
            <option>Company admin</option>
          </select>
          <select id="inv_p" aria-label="Plant" value={invitePlant} onChange={(e) => setInvitePlant(e.target.value)}>
            {plants.map((p, i) => (
              <option key={i} value={i}>
                {p.name}
              </option>
            ))}
          </select>
          <button className="btn" id="inv_go" onClick={handleSendInvite}>
            Send invite
          </button>
        </div>
        <div className="err" id="inv_m">
          {inviteMsg}
        </div>
      </div>

      {/* API Keys */}
      <div className="card" style={{ marginTop: "16px" }}>
        <h2>API keys</h2>
        <p className="hint">
          Read-only keys for pulling findings and telemetry into other systems. Illustrative: the API ships with the backend build.
        </p>
        <div className="row2">
          <button className="btn" id="kgen" onClick={onCreateApiKey}>
            Create read-only key
          </button>
        </div>
        {apiKeys.length ? (
          <>
            <table>
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Scope</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {apiKeys.map((x) => {
                  const showKey = x.isNew ? x.k : `otk_demo_••••••••${x.id}`;
                  return (
                    <tr key={x.id}>
                      <td className="mono">{showKey}</td>
                      <td>Read-only</td>
                      <td>{x.at}</td>
                      <td>
                        <button className="btn ghost" onClick={() => onRevokeApiKey(x.id)}>
                          Revoke
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <p className="hint" style={{ marginTop: "8px" }}>
              Copy a new key now. It is shown once.
            </p>
          </>
        ) : (
          <div className="empty">No keys yet.</div>
        )}
      </div>

      {/* Audit Log */}
      <div className="card" style={{ marginTop: "16px" }}>
        <div className="row2" style={{ margin: 0 }}>
          <h2 style={{ margin: 0 }}>Audit log</h2>
          <span className="sp" />
          <button className="btn ghost" id="acsv" onClick={handleDownloadAuditCsv}>
            Download CSV
          </button>
        </div>
        <p className="hint">Who did what and when, for this session. In production this is stored on the server and cannot be edited.</p>
        {auditLog.length ? (
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {auditLog.slice(0, 30).map((x, idx) => (
                  <tr key={idx}>
                    <td className="mono">{x.ts}</td>
                    <td className="mono">{x.user}</td>
                    <td>{x.a}</td>
                    <td style={{ color: "var(--mut)" }}>{x.d}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty">No activity yet.</div>
        )}
      </div>
    </div>
  );
};

