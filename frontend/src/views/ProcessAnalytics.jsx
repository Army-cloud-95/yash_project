import React, { useState } from "react";
import { TagBadge } from "../components/Badges";
import { ParameterTrendChart } from "../components/Charts";
import { calculateStats, parseTelemetryCsv } from "../utils/helpers";

export const ProcessAnalytics = ({
  plant,
  telemetry,
  telemetryKind,
  thresholds,
  onThresholdsChange,
  onTelemetryAnalyzed,
  onUploadTelemetry,
  t0
}) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileMsg, setFileMsg] = useState("");
  const [isSuccess, setIsSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  const pv = plant.pv;
  const validPoints = telemetry.filter((r) => !r.miss).map((r) => r.p);
  const stats = calculateStats(validPoints);
  const deviations = telemetry.filter((r) => !r.miss && (r.p > thresholds.hi || r.p < thresholds.lo));
  const missingCount = telemetry.filter((r) => r.miss).length;

  const handleFileChange = (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const name = f.name.toLowerCase();
    if (!name.endsWith(".csv")) {
      setFileMsg("Unsupported file type. Use .csv.");
      setIsSuccess(false);
      setSelectedFile(null);
    } else if (f.size > 20 * 1048576) {
      setFileMsg(`File is ${(f.size / 1048576).toFixed(1)} MB. The limit is 20 MB.`);
      setIsSuccess(false);
      setSelectedFile(null);
    } else {
      setSelectedFile(f);
      setFileMsg(`${f.name} is ready. Click the Analyze button.`);
      setIsSuccess(true);
    }
  };

  const handleAnalyzeCsv = async () => {
    if (!selectedFile) {
      setFileMsg("Choose a CSV file first.");
      setIsSuccess(false);
      return;
    }

    setLoading(true);
    setFileMsg(`Analyzing ${selectedFile.name}...`);
    setIsSuccess(false);

    try {
      const text = await selectedFile.text();
      const { tel: newTel, t0: newT0, telKind: newKind, rowCount } = parseTelemetryCsv(text, pv);
      onTelemetryAnalyzed(newTel, newT0, newKind);

      let serverDevs = null;
      if (onUploadTelemetry) {
        try {
          const res = await onUploadTelemetry(selectedFile, {
            column: pv.col,
            lo: thresholds.lo,
            hi: thresholds.hi
          });
          serverDevs = res.deviations;
        } catch (serverErr) {
          console.warn("Backend telemetry upload notification:", serverErr.message);
        }
      }

      const devCount = serverDevs !== null ? serverDevs : newTel.filter((r) => !r.miss && (r.p > thresholds.hi || r.p < thresholds.lo)).length;
      const missCount = newTel.filter((r) => r.miss).length;

      setFileMsg(
        `Analysed ${rowCount} rows from ${selectedFile.name}: ${missCount} missing ${pv.n} values, ${devCount} samples outside ${thresholds.lo}–${thresholds.hi} ${pv.u}.`
      );
      setIsSuccess(true);
    } catch (err) {
      setFileMsg(err.message || "Could not read this file.");
      setIsSuccess(false);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1>Industrial Process Analytics</h1>
      <p className="sub">
        Plant parameter: {pv.n} (column {pv.col}). The CSV also needs timestamp, pressure_bar, temperature_c, voltage_v, current_a,
        motor_state and valve_state.
      </p>

      {/* Drop / file input */}
      <div className="drop">
        Drop a telemetry CSV here (max 20 MB)
        <br />
        <input
          type="file"
          id="f3"
          accept=".csv"
          aria-label="Telemetry CSV"
          disabled={loading}
          onChange={handleFileChange}
        />{" "}
        <button className="btn" id="a3" disabled={loading} onClick={handleAnalyzeCsv}>
          {loading ? "Analyzing..." : "Analyze telemetry"}
        </button>
      </div>

      <div className="err" id="e3" style={{ color: isSuccess ? "var(--ok)" : "" }}>
        {fileMsg}
      </div>

      {/* Main Chart Card */}
      <div className="card" style={{ marginTop: "16px" }}>
        <div className="row2">
          <h2 style={{ margin: 0 }}>
            {pv.n} ({pv.u}) <TagBadge kind={telemetryKind} />
          </h2>
          <span className="sp" />
          <label>
            Upper limit{" "}
            <input
              type="range"
              id="hi"
              min={plant.thr.hi - plant.rng}
              max={plant.thr.hi + plant.rng}
              step={plant.st}
              value={thresholds.hi}
              onChange={(e) => onThresholdsChange({ ...thresholds, hi: +e.target.value })}
            />{" "}
            <span className="mono">{thresholds.hi}</span>
          </label>
          <label>
            Lower limit{" "}
            <input
              type="range"
              id="lo"
              min={plant.thr.lo - plant.rng}
              max={plant.thr.lo + plant.rng}
              step={plant.st}
              value={thresholds.lo}
              onChange={(e) => onThresholdsChange({ ...thresholds, lo: +e.target.value })}
            />{" "}
            <span className="mono">{thresholds.lo}</span>
          </label>
        </div>
        <p className="hint">
          Trend over time with the allowed band shaded. Red points are outside the limits and grey points are missing samples.
          Move the sliders to set the limits.
        </p>
        <ParameterTrendChart tel={telemetry} thr={thresholds} plant={plant} pv={pv} t0={t0} width={900} height={260} />
      </div>

      {/* KPI Stats */}
      <div className="grid g4" style={{ marginTop: "16px" }}>
        {[
          ["Mean", `${stats.m.toFixed(2)} ${pv.u}`, "Average of all valid samples."],
          ["Median", `${stats.med.toFixed(2)} ${pv.u}`, "Middle value. Less affected by short spikes."],
          ["Std deviation", `${stats.sd.toFixed(2)} ${pv.u}`, "How far readings spread around the mean."],
          ["Coeff. of variation", `${stats.cv.toFixed(1)}%`, "Std deviation as a share of the mean. Compares stability."],
          ["Out of range", deviations.length, "Samples beyond the configured limits."],
          ["Missing values", missingCount, "Gaps in the series that were skipped."]
        ].map(([title, val, desc]) => (
          <div key={title} className="card kpi">
            <span>{title}</span>
            <b>{val}</b>
            <span style={{ fontSize: "12px" }}>{desc}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
