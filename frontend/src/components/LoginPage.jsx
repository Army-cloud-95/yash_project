import React, { useState } from "react";

export const LoginPage = ({ users, onSignIn, onBackToHome, onLogAudit }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSignIn = async () => {
    const trimmedU = username.trim();
    if (!trimmedU || !password) {
      setError("Please enter both username and password.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      await onSignIn(trimmedU, password);
    } catch (err) {
      setError(err.message || "Failed to sign in.");
      if (onLogAudit) {
        onLogAudit("Failed sign-in", trimmedU.slice(0, 40));
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSelectAccount = (acc) => {
    setUsername(acc.u);
    setPassword(acc.p || "");
    setError("");
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") {
      handleSignIn();
    }
  };

  return (
    <div className="login">
      <div className="lcard">
        <div className="logo" style={{ padding: "0 0 6px" }}>
          <i />
          OT Sentinel
        </div>
        <p className="sub" style={{ marginBottom: "18px" }}>
          Industrial cybersecurity and process analytics
        </p>

        <label>
          Username
          <input
            id="lu"
            autoComplete="username"
            value={username}
            disabled={loading}
            onChange={(e) => {
              setUsername(e.target.value);
              setError("");
            }}
            onKeyDown={handleKeyDown}
          />
        </label>

        <label>
          Password
          <input
            id="lpw"
            type="password"
            autoComplete="current-password"
            value={password}
            disabled={loading}
            onChange={(e) => {
              setPassword(e.target.value);
              setError("");
            }}
            onKeyDown={handleKeyDown}
          />
        </label>

        <div className="err" id="le" role="alert">
          {error}
        </div>

        <button className="btn" id="ls" style={{ width: "100%" }} disabled={loading} onClick={handleSignIn}>
          {loading ? "Signing in..." : "Sign in"}
        </button>

        <button className="btn ghost" id="lback" style={{ width: "100%", marginTop: "10px" }} onClick={onBackToHome}>
          Back to home
        </button>

        <h2 style={{ margin: "22px 0 2px", fontSize: "13px", color: "var(--mut)" }}>Accounts</h2>
        <p className="hint" style={{ margin: "0 0 4px" }}>
          Click an account to fill in its credentials. The company account sees every plant. A plant account sees only its own plant.
        </p>

        {users
          .filter((x) => x.p)
          .map((x) => (
            <button key={x.u} className="acct" data-u={x.u} disabled={loading} onClick={() => handleSelectAccount(x)}>
              <span>
                <b>{x.role}</b> · {x.name}
              </span>
              <span className="mono">{x.u}</span>
            </button>
          ))}
      </div>
    </div>
  );
};
