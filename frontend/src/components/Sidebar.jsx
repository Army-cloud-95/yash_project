import React from "react";
import { ICONS, VIEWS } from "../data/initialData";

export const Sidebar = ({ currentView, onSelectView, isAdmin, org }) => {
  const visibleViews = VIEWS.filter(([k]) => {
    if (k === "f" || k === "o") {
      return isAdmin;
    }
    return true;
  });

  return (
    <aside id="nav" aria-label="Modules">
      <div className="logo">
        <i />
        OT Sentinel
      </div>

      {visibleViews.map(([k, name]) => (
        <button
          key={k}
          className="nav"
          data-k={k}
          aria-current={k === currentView ? "page" : undefined}
          onClick={() => onSelectView(k)}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d={ICONS[k]} />
          </svg>
          {name}
        </button>
      ))}

      <div className="side-foot">
        <b>{org.name}</b>
        <br />
        {org.plan} plan
        <br />
        Read-only analysis. No commands are sent to PLCs.
      </div>
    </aside>
  );
};

