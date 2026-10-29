import React from "react";

export const Sparkline = ({ data, width = 160, height = 36 }) => {
  if (!data || data.length < 2) return null;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const points = data
    .map((v, i) => {
      const x = ((i / (data.length - 1)) * width).toFixed(1);
      const y = (height - 2 - ((v - min) / range) * (height - 4)).toFixed(1);
      return `${i === 0 ? "M" : "L"}${x} ${y}`;
    })
    .join("");

  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} preserveAspectRatio="none" aria-hidden="true">
      <path d={points} fill="none" stroke="#22d3ee" strokeWidth="1.5" />
    </svg>
  );
};

