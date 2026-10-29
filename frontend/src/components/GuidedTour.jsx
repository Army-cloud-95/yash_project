import React from "react";
import { GUIDE_STEPS } from "../data/initialData";

export const GuidedTour = ({ onClose, onNavigate, isAdmin }) => {
  const steps = GUIDE_STEPS.filter((g) => g[0] !== "f" || isAdmin);

  return (
    <div className="card" style={{ marginBottom: "16px", borderColor: "#146075" }}>
      <div className="row2" style={{ margin: "0 0 8px" }}>
        <h2 style={{ margin: 0 }}>Evaluator walkthrough</h2>
        <span className="sp" />
        <button className="btn ghost" id="gx" onClick={onClose}>
          Close
        </button>
      </div>
      <ol style={{ margin: 0, paddingLeft: "20px", color: "var(--mut)" }}>
        {steps.map(([k, t, d]) => (
          <li key={k} style={{ margin: "6px 0" }}>
            <button className="btn ghost" data-go={k} style={{ padding: "2px 10px", marginRight: "6px" }} onClick={() => onNavigate(k)}>
              {t}
            </button>
            {d}
          </li>
        ))}
      </ol>
    </div>
  );
};

