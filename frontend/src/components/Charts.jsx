import React from "react";
import { formatTime } from "../utils/helpers";

export const LiveFeedChart = ({ buf, plant, thr, pv, showStats = true }) => {
  if (!buf || buf.length === 0) return null;
  const w = 900;
  const h = 90;
  const g = plant.thr.hi - plant.thr.lo;
  const lo = plant.thr.lo - g * 0.2;
  const hi = plant.thr.hi + g * 0.2;
  const ys = (v) => h - ((v - lo) / (hi - lo)) * h;

  const last = buf[buf.length - 1];
  const bad = last > thr.hi || last < thr.lo;

  const points = buf
    .map((v, i) => {
      const x = (((i + 60 - buf.length) / 59) * w).toFixed(1);
      const y = ys(v).toFixed(1);
      return `${i === 0 ? "M" : "L"}${x} ${y}`;
    })
    .join("");

  return (
    <div>
      {showStats && (
        <div className="row2">
          <b className="mono" style={{ fontSize: "26px", color: bad ? "var(--crit)" : "var(--cy)" }}>
            {last.toFixed(2)} {pv.u}
          </b>
          <span className={`sev s-${bad ? "high" : "low"}`}>{bad ? "Outside limits" : "Within limits"}</span>
          <span className="mono" style={{ color: "var(--mut)" }}>
            1 sample per second, generated in this page
          </span>
        </div>
      )}
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none" role="img" aria-label="Simulated live feed">
        <line x1="0" x2={w} y1={ys(thr.hi)} y2={ys(thr.hi)} stroke="#ff9f43" strokeDasharray="4 3" />
        <line x1="0" x2={w} y1={ys(thr.lo)} y2={ys(thr.lo)} stroke="#ff9f43" strokeDasharray="4 3" />
        <path d={points} fill="none" stroke="#22d3ee" strokeWidth="2" />
      </svg>
    </div>
  );
};

export const ParameterTrendChart = ({ tel, thr, plant, pv, t0, width = 640, height = 220 }) => {
  if (!tel || tel.length === 0) return null;

  const N = tel.length;
  const ptel = tel.filter((r) => !r.miss).map((r) => r.p);
  const P = [34, 10, 22, 30]; // left, right, bottom, top padding
  const xs = (i) => P[0] + (i / Math.max(1, N - 1)) * (width - P[0] - P[1]);

  const m = (plant.thr.hi - plant.thr.lo) * 0.1;
  const mn = Math.floor(Math.min(thr.lo, ...ptel) - m);
  const mx = Math.ceil(Math.max(thr.hi, ...ptel) + m);
  const sp = Math.max(1, Math.ceil((mx - mn) / 6));
  const ys = (v) => height - P[2] - ((v - mn) / (mx - mn)) * (height - P[2] - P[3]);

  let path = "";
  tel.forEach((r, i) => {
    if (!r.miss) {
      const prevWasValid = i > 0 && !tel[i - 1].miss;
      path += (prevWasValid ? "L" : "M") + xs(i).toFixed(1) + " " + ys(r.p).toFixed(1);
    }
  });

  const devs = tel.filter((r) => !r.miss && (r.p > thr.hi || r.p < thr.lo));
  const d0 = devs[0];
  const di = d0 ? tel.indexOf(d0) : -1;

  const numGridLines = Math.floor((mx - mn) / sp) + 1;
  const gridVals = Array.from({ length: numGridLines }, (_, k) => mn + k * sp);

  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" role="img" aria-label="Parameter trend with threshold band">
      <rect
        x={P[0]}
        y={ys(thr.hi)}
        width={width - P[0] - P[1]}
        height={Math.max(0, ys(thr.lo) - ys(thr.hi))}
        fill="rgba(34,211,238,.07)"
      />
      {gridVals.map((v) => (
        <React.Fragment key={v}>
          <line x1={P[0]} x2={width - P[1]} y1={ys(v)} y2={ys(v)} stroke="#1f2f4d" />
          <text x="2" y={ys(v) + 4}>
            {v}
          </text>
        </React.Fragment>
      ))}
      <line x1={P[0]} x2={width - P[1]} y1={ys(thr.hi)} y2={ys(thr.hi)} stroke="#ff9f43" strokeDasharray="4 3" />
      <line x1={P[0]} x2={width - P[1]} y1={ys(thr.lo)} y2={ys(thr.lo)} stroke="#ff9f43" strokeDasharray="4 3" />
      <path d={path} fill="none" stroke="#22d3ee" strokeWidth="2" />
      {tel.map((r, i) =>
        r.miss ? (
          <circle key={`miss-${i}`} cx={xs(i)} cy={height - P[2]} r="3" fill="#8fa0bd">
            <title>Missing value</title>
          </circle>
        ) : null
      )}
      {tel.map((r, i) =>
        !r.miss && (r.p > thr.hi || r.p < thr.lo) ? (
          <circle key={`dev-${i}`} cx={xs(i)} cy={ys(r.p)} r="3" fill="#ff5d6c" />
        ) : null
      )}
      {di >= 0 && (
        <>
          <line x1={xs(di)} x2={xs(di)} y1={P[3]} y2={height - P[2]} stroke="#ff5d6c" strokeOpacity="0.5" />
          <text x={xs(di) + 5} y={P[3] + 8}>
            first deviation {formatTime(d0.t, t0)}
          </text>
        </>
      )}
      <text x={P[0]} y={height - 4}>
        {formatTime(tel[0].t, t0)}
      </text>
      <text x={width - 70} y={height - 4}>
        {formatTime(tel[N - 1].t, t0)}
      </text>
    </svg>
  );
};

