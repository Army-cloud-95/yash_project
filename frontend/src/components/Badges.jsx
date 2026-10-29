import React from "react";

export const SeverityBadge = ({ sev }) => {
  if (!sev) return null;
  const label = sev.charAt(0).toUpperCase() + sev.slice(1);
  return <span className={`sev s-${sev}`}>{label}</span>;
};

export const TagBadge = ({ kind }) => {
  if (kind === "sim") return <span className="tag t-sim">Simulated</span>;
  if (kind === "obs") return <span className="tag t-obs">Observed</span>;
  if (kind === "inf") return <span className="tag t-inf">Inferred</span>;
  if (kind === "conf") return <span className="tag t-conf">Analyst-confirmed</span>;
  if (kind === "extracted") return <span className="tag t-obs">Extracted</span>;
  if (kind === "verified") return <span className="tag t-obs">Verified</span>;
  if (kind === "needs_review") return <span className="tag t-sim">Needs review</span>;
  return null;
};

