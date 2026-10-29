import { BASE_T0 } from "../data/initialData";

export const formatTime = (seconds, t0 = BASE_T0) => {
  return new Date(t0 + Math.round(seconds) * 1000).toISOString().slice(11, 19);
};

export const calculateStats = (arr) => {
  if (!arr || arr.length === 0) {
    return { m: 0, med: 0, sd: 0, cv: 0 };
  }
  const m = arr.reduce((x, y) => x + y, 0) / arr.length;
  const s = [...arr].sort((x, y) => x - y);
  const med = s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
  const variance = arr.reduce((x, y) => x + (y - m) ** 2, 0) / Math.max(1, arr.length - 1);
  const sd = Math.sqrt(variance);
  const cv = m !== 0 ? (sd / m) * 100 : 0;
  return { m, med, sd, cv };
};

export const parsePdfText = (text) => {
  const normalized = text.replace(/\s+/g, " ");
  const match = (re, maxLen = 300) => {
    const m = normalized.match(re);
    return m ? m[1].trim().slice(0, maxLen) : null;
  };
  const mfr = match(/Manufacturer:\s*(.+?)\s+(?:Model:|Firmware|Communication|Protocols:)/i);
  const model = match(/Model:\s*(.+?)\s+(?:Firmware|Communication|Protocols:)/i);
  const fw = match(/Firmware(?: version)?:\s*(\S+)/i);
  const proto = match(/Protocols:\s*(.+?)\s+(?:Interfaces:|Security|Lifecycle)/i);
  const ifc = match(/Interfaces:\s*(.+?)\s+(?:Security|Lifecycle)/i);
  const sec = match(/Security features\s*(.+?)\s+Lifecycle/i);
  const life = match(/Lifecycle\s*(.+)$/i);
  const name = mfr && model ? `${mfr} ${model}` : model || "";

  return { mfr, model, fw, proto, ifc, sec, life, name };
};

export const readPdfFile = async (file) => {
  const pdfjsLib = window.pdfjsLib;
  if (!pdfjsLib) {
    throw new Error("PDF parser library not loaded yet.");
  }
  pdfjsLib.GlobalWorkerOptions.workerSrc = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
  const data = await file.arrayBuffer();
  const doc = await pdfjsLib.getDocument({ data, isEvalSupported: false }).promise;
  let text = "";
  const maxPages = Math.min(doc.numPages, 20);
  for (let i = 1; i <= maxPages; i++) {
    const page = await doc.getPage(i);
    const content = await page.getTextContent();
    text += content.items.map((x) => x.str).join(" ") + " ";
  }
  return text;
};

export const parsePcapBinary = (buffer, allowList, ips, t0 = BASE_T0) => {
  const v = new DataView(buffer);
  if (buffer.byteLength < 24 || v.getUint32(0, true) !== 0xa1b2c3d4) {
    throw new Error("This preview reads classic .pcap files with microsecond timestamps. Convert pcapng with: editcap -F pcap in.pcapng out.pcap");
  }
  if (v.getUint32(20, true) !== 1) {
    throw new Error("Only Ethernet captures are supported.");
  }

  const portNames = { 502: "Modbus/TCP", 20000: "DNP3", 102: "S7Comm", 4840: "OPC UA", 44818: "EtherNet/IP" };
  const ep = {};
  const fc = {};
  const ev = [];
  const dnp = {};
  const ipString = (offset) => [0, 1, 2, 3].map((k) => v.getUint8(offset + k)).join(".");

  const getAssetName = (ip) => {
    const entry = Object.entries(ips).find(([, val]) => val === ip);
    return entry ? entry[0] : "Unmapped";
  };

  let o = 24;
  let packetCount = 0;

  while (o + 16 <= buffer.byteLength && packetCount < 200000) {
    const ts = v.getUint32(o, true) + v.getUint32(o + 4, true) / 1e6;
    const l = v.getUint32(o + 8, true);
    const p = o + 16;
    o = p + l;
    packetCount++;

    if (l < 54 || o > buffer.byteLength || v.getUint16(p + 12) !== 0x0800 || v.getUint8(p + 23) !== 6) {
      continue;
    }

    const t = p + 14 + (v.getUint8(p + 14) & 15) * 4;
    const src = ipString(p + 26);
    const dst = ipString(p + 30);
    const sp = v.getUint16(t);
    const dp = v.getUint16(t + 2);
    const pl = t + (v.getUint8(t + 12) >> 4) * 4;
    const len = p + l - pl;
    const rel = ts - t0 / 1000;

    for (const [ip, pt] of [[src, sp], [dst, dp]]) {
      const q = (ep[ip] = ep[ip] || new Set());
      if (portNames[pt]) q.add(portNames[pt]);
    }

    if (dp === 502 && len >= 8) {
      const code = v.getUint8(pl + 7);
      fc[code] = (fc[code] || 0) + 1;
      if ([5, 6, 15, 16].includes(code) && !allowList.includes(src)) {
        ev.push({
          t: rel,
          asset: getAssetName(dst),
          title: `Modbus write (FC ${code}) from unlisted host ${src}`,
          sev: "high",
          kind: "obs",
          rule: "R-MB-03: write function code from a source not in the allow-list",
          ev: `Frame ${packetCount}, ${formatTime(rel, t0)}, ${src} → ${dst}:502, FC ${code}, register ${len >= 10 ? v.getUint16(pl + 8) + 40001 : "unknown"}`,
          verify: `Confirm ${src} is an authorised engineering station and review the change ticket.`
        });
      }
    }

    if (dp === 20000 && len >= 2 && v.getUint8(pl) === 5 && v.getUint8(pl + 1) === 0x64) {
      const k = src + ">" + dst;
      dnp[k] = dnp[k] || { t: rel, n: 0, fr: packetCount, src, dst };
      dnp[k].n++;
    }
  }

  Object.values(dnp).forEach((d) => {
    ev.push({
      t: d.t,
      asset: getAssetName(d.dst),
      title: `Cleartext DNP3 traffic to ${d.dst}`,
      sev: "low",
      kind: "obs",
      rule: "R-PR-01: industrial protocol on a routed segment with no encryption seen",
      ev: `Frame ${d.fr}, ${d.n} DNP3 frames ${d.src} → ${d.dst}:20000. Secure authentication was not checked.`,
      verify: "Check whether this link crosses a trusted zone boundary."
    });
  });

  ev.sort((a, b) => a.t - b.t);

  const netStats = {
    eps: Object.entries(ep)
      .sort()
      .map(([ip, q]) => [ip, [...q].join(", ") || "Other"]),
    fc:
      Object.entries(fc)
        .map(([k, c]) => `FC ${String(k).padStart(2, "0")} ×${c}`)
        .join(" · ") || "No Modbus requests"
  };

  return { events: ev, netStats, packetCount };
};

export const parseTelemetryCsv = (text, pv) => {
  const reqCols = ["timestamp", "pressure_bar", "temperature_c", "voltage_v", "current_a", "motor_state", "valve_state"];
  const lines = text.trim().split(/\r?\n/);
  const header = lines[0].split(",").map((s) => s.trim().toLowerCase());
  const missing = reqCols.filter((c) => !header.includes(c));

  if (missing.length) {
    throw new Error(`Missing columns: ${missing.join(", ")}. Expected: ${reqCols.join(", ")}.`);
  }

  if (lines.length < 3 || lines.length > 20001) {
    throw new Error("The file needs 2 to 20,000 data rows.");
  }

  const ix = (c) => header.indexOf(c);
  const rows = [];

  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(",");
    const tsStr = cols[ix("timestamp")];
    const ms = Date.parse(tsStr);
    if (isNaN(ms)) {
      throw new Error(`Row ${i + 1}: "${tsStr}" is not a valid timestamp. Use ISO 8601, for example 2026-10-14T10:00:00Z.`);
    }

    const raw = (cols[ix(pv.col)] || "").trim();
    const p = raw === "" ? NaN : +raw;
    if (raw !== "" && (isNaN(p) || p < pv.lo || p > pv.hi)) {
      throw new Error(`Row ${i + 1}: ${pv.n} "${raw}" is not a number between ${pv.lo} and ${pv.hi} ${pv.u}. Check the unit.`);
    }

    rows.push({
      ms,
      p,
      temp: cols[ix("temperature_c")],
      v: cols[ix("voltage_v")],
      mot: cols[ix("motor_state")],
      valve: cols[ix("valve_state")],
      lab: (cols[header.indexOf("data_label")] || "").trim()
    });
  }

  if (rows.filter((r) => !isNaN(r.p)).length < 2) {
    throw new Error(`Fewer than 2 rows have a ${pv.n} value.`);
  }

  const t0 = rows[0].ms;
  const tel = rows.map((r) => ({
    t: (r.ms - t0) / 1000,
    p: r.p,
    temp: r.temp,
    v: r.v,
    mot: r.mot,
    valve: r.valve,
    miss: isNaN(r.p)
  }));

  const telKind = rows.every((r) => r.lab === "SYNTHETIC") ? "sim" : "obs";

  return { tel, t0, telKind, rowCount: tel.length };
};

export const downloadCsvFile = (filename, content) => {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

