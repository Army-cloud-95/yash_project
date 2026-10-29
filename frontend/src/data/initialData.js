export const BASE_T0 = Date.UTC(2026, 9, 14, 10, 0, 0);

export const ICONS = {
  v: "M9 3h6M10 3v6l-5 9a2 2 0 002 3h10a2 2 0 002-3l-5-9V3M8 15h8",
  o: "M3 21h18M5 21V7l7-4 7 4v14M9 21v-6h6v6",
  r: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM9 12l2 2 4-4",
  l: "M2 12h4l2-6 4 12 3-9 2 3h5",
  f: "M12 3l9 5v2H3V8zM5 12v7M10 12v7M14 12v7M19 12v7M3 21h18",
  s: "M4 6c0-1.5 3.6-3 8-3s8 1.5 8 3-3.6 3-8 3-8-1.5-8-3zM4 6v6c0 1.5 3.6 3 8 3s8-1.5 8-3V6M4 12v6c0 1.5 3.6 3 8 3s8-1.5 8-3v-6",
  d: "M3 3h7v7H3zM14 3h7v4h-7zM14 10h7v11h-7zM3 13h7v8H3z",
  a: "M4 6h16M4 12h16M4 18h10",
  n: "M5 12a7 7 0 0114 0M8.5 12a3.5 3.5 0 017 0M12 12v.01M12 16v5",
  p: "M3 17l5-6 4 3 5-8 4 5",
  c: "M6 6a3 3 0 100 .01M18 18a3 3 0 100 .01M18 6a3 3 0 100 .01M8.5 7.5l7 9M9 6h6",
  t: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"
};

export const VIEWS = [
  ["f", "Fleet Overview"],
  ["d", "Plant Overview"],
  ["l", "Live Operations"],
  ["a", "Asset Explorer"],
  ["n", "Network Analysis"],
  ["p", "Process Analytics"],
  ["c", "Correlation"],
  ["t", "Threat Intel & Reports"],
  ["r", "Risk & Compliance"],
  ["v", "Validation"],
  ["s", "Data Sources"],
  ["o", "Organization"]
];

export const GUIDE_STEPS = [
  ["f", "Fleet", "Compare the four plants by risk and open findings."],
  ["d", "Plant overview", "Watch the simulated live feed, then press Simulate excursion."],
  ["l", "Live operations", "Connect a source, then review live analysis, asset management and security events."],
  ["a", "Assets", "Import a datasheet and review the extracted values."],
  ["n", "Network", "Analyze the sample capture and read the evidence behind each rule."],
  ["p", "Process", "Analyze telemetry and move the thresholds."],
  ["c", "Correlation", "Widen the window. Timing is not proof of cause."],
  ["t", "Reports", "Check the ATT&CK mapping and download the CSV."],
  ["r", "Risk & compliance", "See the posture score, how it is calculated and the readiness checklist."],
  ["v", "Validation", "Read the security model and the measured test results."],
  ["s", "Data sources", "See how live data would be collected, read-only."]
];

export const INITIAL_USERS = [
  { u: "company.admin", p: "Admin@2026", name: "Company Admin", role: "Company admin", plants: [0, 1, 2, 3], status: "Active" },
  { u: "plant.a", p: "PlantA@2026", name: "Plant A Operator", role: "Plant user", plants: [0], status: "Active" },
  { u: "plant.b", p: "PlantB@2026", name: "Plant B Operator", role: "Plant user", plants: [1], status: "Active" },
  { u: "plant.c", p: "PlantC@2026", name: "Plant C Operator", role: "Plant user", plants: [2], status: "Active" },
  { u: "plant.d", p: "PlantD@2026", name: "Plant D Operator", role: "Plant user", plants: [3], status: "Active" }
];

export const SCRIPT_EVENTS = [
  [
    { at: 8, c: "Asset", sev: "medium", t: "Unlisted host 10.20.4.77 seen on Modbus/TCP", r: "R-AS-01: host not in the asset inventory", a: "PLC-01", ip: "10.20.4.77" },
    { at: 18, c: "Cyber", sev: "high", t: "Modbus write (FC 16) from unlisted host 10.20.4.77", r: "R-MB-03: write function code from a source not in the allow-list", a: "PLC-01", ip: "10.20.4.77", e: "10.20.4.77 → 10.20.4.10:502, FC 16, register 40021" },
    { at: 32, c: "Cyber", sev: "low", t: "Cleartext DNP3 session to RTU-04", r: "R-PR-01: industrial protocol with no encryption seen", a: "RTU-04", ip: "10.20.4.50", e: "10.20.4.50 → 10.20.4.21:20000" }
  ],
  [
    { at: 15, c: "Cyber", sev: "low", t: "Cleartext DNP3 session to RTU-02", r: "R-PR-01: industrial protocol with no encryption seen", a: "RTU-02", ip: "10.40.1.50", e: "10.40.1.50 → 10.40.1.21:20000" }
  ],
  [
    { at: 10, c: "Asset", sev: "medium", t: "Unlisted host 10.30.1.99 seen on Modbus/TCP", r: "R-AS-01: host not in the asset inventory", a: "PLC-01", ip: "10.30.1.99" },
    { at: 20, c: "Cyber", sev: "high", t: "Modbus write (FC 6) from unlisted host 10.30.1.99", r: "R-MB-03: write function code from a source not in the allow-list", a: "PLC-01", ip: "10.30.1.99", e: "10.30.1.99 → 10.30.1.10:502, FC 6, register 40008" },
    { at: 34, c: "Cyber", sev: "low", t: "Cleartext DNP3 session to RTU-03", r: "R-PR-01: industrial protocol with no encryption seen", a: "RTU-03", ip: "10.30.1.50", e: "10.30.1.50 → 10.30.1.22:20000" }
  ],
  []
];

export const VALIDATION_DATA = {
  network: {
    "R-MB-03": { tp: 80, fp: 0, fn: 0, tn: 320, precision: 1.0, recall: 1.0 },
    "R-AS-01": { tp: 160, fp: 0, fn: 0, tn: 240, precision: 1.0, recall: 1.0 },
    "R-PR-01": { tp: 40, fp: 0, fn: 0, tn: 360, precision: 1.0, recall: 1.0 }
  },
  scenario_pass_rate_pct: {
    benign: 100.0,
    allowed_write: 100.0,
    unlisted_write: 100.0,
    unlisted_read: 100.0,
    dnp3_cleartext: 100.0,
    write_response_direction: 100.0,
    write_on_other_port: 100.0,
    non_modbus_payload_on_502: 100.0,
    truncated_capture: 100.0,
    retransmitted_write: 100.0
  },
  scenarios_per_kind: 40,
  crashes: 0,
  duplicate_findings_on_retransmit: 0,
  telemetry_detection: [
    { peak_above_baseline: 0.5, series_exceeding_limit: 0.0, detected: 0.0 },
    { peak_above_baseline: 1.0, series_exceeding_limit: 0.5, detected: 0.5 },
    { peak_above_baseline: 1.5, series_exceeding_limit: 100.0, detected: 100.0 },
    { peak_above_baseline: 2.0, series_exceeding_limit: 100.0, detected: 100.0 },
    { peak_above_baseline: 3.0, series_exceeding_limit: 100.0, detected: 100.0 }
  ],
  telemetry_false_alarms: [
    { noise_sd: 0.1, false_alarm_series_pct: 0.0 },
    { noise_sd: 0.3, false_alarm_series_pct: 0.5 },
    { noise_sd: 0.5, false_alarm_series_pct: 74.0 },
    { noise_sd: 0.7, false_alarm_series_pct: 100.0 }
  ],
  correlation: [
    { window_s: 30, planted_chain_found_pct: 10.5, linked_events_that_are_true_pct: 84.8, unrelated_scenarios_linked_pct: 9.5 },
    { window_s: 60, planted_chain_found_pct: 44.5, linked_events_that_are_true_pct: 85.2, unrelated_scenarios_linked_pct: 16.0 },
    { window_s: 120, planted_chain_found_pct: 100.0, linked_events_that_are_true_pct: 85.8, unrelated_scenarios_linked_pct: 33.5 },
    { window_s: 300, planted_chain_found_pct: 100.0, linked_events_that_are_true_pct: 66.0, unrelated_scenarios_linked_pct: 63.0 },
    { window_s: 600, planted_chain_found_pct: 100.0, linked_events_that_are_true_pct: 48.3, unrelated_scenarios_linked_pct: 90.0 }
  ]
};

const genTelemetry = (st, h, base, amp, sd) =>
  [...Array(120)].map((_, i) => {
    let p = base + amp * Math.sin(i / 6) + 0.08 * Math.sin(i * 2.3 + sd);
    if (st >= 0) {
      if (i >= st && i <= st + 12) p += ((i - st + 1) / 12) * h;
      if (i > st + 12 && i <= st + 24) p += ((st + 24 - i) / 12) * h;
    }
    return {
      t: i * 30,
      p: +p.toFixed(2),
      temp: 71,
      v: 400,
      mot: "ON",
      valve: "OPEN",
      miss: false
    };
  });

const dnpEvent = (t, a, ip, ev) => ({
  t,
  asset: a,
  title: `Cleartext DNP3 traffic to ${ip}`,
  sev: "low",
  kind: "obs",
  rule: "R-PR-01: industrial protocol on a routed segment with no encryption seen",
  ev
});

export const createInitialPlants = () => {
  const plantATel = [...Array(120)].map((_, i) => {
    let p = 6.2 + 0.25 * Math.sin(i / 6) + 0.08 * Math.sin(i * 2.3);
    if (i >= 84 && i <= 96) p += ((i - 83) / 12) * 2.2;
    if (i > 96 && i <= 108) p += ((108 - i) / 12) * 2.2;
    return {
      t: i * 30,
      p: +p.toFixed(2),
      temp: +(71 + 1.8 * Math.sin(i / 9)).toFixed(1),
      v: +(400 + 3 * Math.sin(i / 5)).toFixed(0),
      mot: i % 40 < 35 ? "ON" : "ON",
      valve: i >= 84 ? "OPEN" : "CLOSED",
      miss: i === 31 || i === 32
    };
  });

  return [
    {
      id: 1,
      name: "Plant A · Boiler House",
      site: "Steam and utilities",
      assets: [
        {
          id: "PLC-01",
          name: "Boiler line controller",
          mfr: "Northwind Controls",
          model: "NC-400",
          fw: "V2.9.4",
          proto: "PROFINET, S7Comm, Modbus/TCP",
          sec: "Access protection, TLS (S7Comm+)",
          life: "Active product lifecycle (datasheet statement)",
          ver: true,
          src: "nc-400-datasheet.pdf, p.3"
        },
        {
          id: "RTU-04",
          name: "Remote pump RTU",
          mfr: "Helios Automation",
          model: "HX-575",
          fw: null,
          proto: "Modbus/TCP, DNP3",
          sec: null,
          life: null,
          ver: false,
          src: "hx-575-datasheet.pdf, p.1"
        },
        {
          id: "HMI-02",
          name: "Operator panel",
          mfr: "Unknown",
          model: "Unknown",
          fw: null,
          proto: "OPC UA",
          sec: null,
          life: null,
          ver: false,
          src: "manual upload (no datasheet)"
        }
      ],
      ips: { "PLC-01": "10.20.4.10", "RTU-04": "10.20.4.21", "HMI-02": "10.20.4.50" },
      net: [
        {
          t: 41 * 60 + 12,
          asset: "PLC-01",
          title: "Modbus write (FC 16) from unlisted host 10.20.4.77",
          sev: "high",
          kind: "obs",
          rule: "R-MB-03: write function code from source not in allow-list",
          ev: "Frame 4812, 10:01:12, 10.20.4.77 → 10.20.4.10:502, FC 16 Write Multiple Registers, addr 40021, qty 2",
          src_ip: "10.20.4.77"
        },
        {
          t: 5 * 60 + 20,
          asset: "RTU-04",
          title: "Unencrypted DNP3 session to RTU",
          sev: "low",
          kind: "obs",
          rule: "R-PR-01: cleartext industrial protocol on routed segment",
          ev: "Frames 211–340, 10.20.4.50 → 10.20.4.21:20000, no secure authentication objects seen"
        }
      ],
      plc: [
        {
          t: 41 * 60 + 40,
          asset: "PLC-01",
          title: "Holding register 40021 changed; CPU mode stayed RUN",
          ev: "Audit record #918 (simulation export), user: unknown"
        }
      ],
      tel: plantATel,
      pv: { col: "pressure_bar", n: "Drum pressure", u: "bar", lo: 0, hi: 100 },
      rng: 1.5,
      st: 0.1,
      thr: { hi: 7.5, lo: 5 },
      allow: ["10.20.4.50", "10.20.4.30"],
      fc: "FC 03 read ×360 · FC 16 write ×1"
    },
    {
      id: 2,
      name: "Plant B · Water Treatment",
      site: "Intake and distribution",
      assets: [
        {
          id: "PLC-01",
          name: "Intake pump controller",
          mfr: "Helios Automation",
          model: "HX-300",
          fw: "V1.8.2",
          proto: "Modbus/TCP, DNP3",
          ifc: "2 x Ethernet, 1 x RS-485",
          sec: "Role-based access, audit log",
          life: "Active product (datasheet statement)",
          ver: true,
          src: "hx-300-datasheet.pdf"
        },
        {
          id: "RTU-02",
          name: "Reservoir level RTU",
          mfr: "Helios Automation",
          model: "HX-575",
          fw: null,
          proto: "DNP3",
          sec: null,
          life: null,
          ver: false,
          src: "hx-575-datasheet.pdf"
        },
        {
          id: "HMI-01",
          name: "Control room HMI",
          mfr: null,
          model: null,
          fw: null,
          proto: "OPC UA",
          sec: null,
          life: null,
          ver: false,
          src: "manual entry"
        }
      ],
      ips: { "PLC-01": "10.40.1.10", "RTU-02": "10.40.1.21", "HMI-01": "10.40.1.50" },
      net: [
        dnpEvent(420, "RTU-02", "10.40.1.21", "Frames 88–140, 10.40.1.50 → 10.40.1.21:20000. Secure authentication was not checked.")
      ],
      plc: [],
      tel: genTelemetry(-1, 0, 12.5, 0.6, 1),
      pv: { col: "current_a", n: "Pump motor current", u: "A", lo: 0, hi: 500 },
      rng: 3,
      st: 0.1,
      thr: { lo: 9, hi: 16 },
      allow: ["10.40.1.50"],
      fc: "FC 03 read ×720"
    },
    {
      id: 3,
      name: "Plant C · Power Substation",
      site: "Low-voltage distribution",
      assets: [
        {
          id: "PLC-01",
          name: "Bay protection controller",
          mfr: "Northwind Controls",
          model: "NC-250",
          fw: "V2.4.0",
          proto: "Modbus/TCP",
          ifc: "2 x Ethernet",
          sec: "Signed firmware, audit log",
          life: "Active product (datasheet statement)",
          ver: true,
          src: "nc-250-datasheet.pdf"
        },
        {
          id: "RTU-03",
          name: "Transformer monitor RTU",
          mfr: "Vertex Monitoring",
          model: "VM-12",
          fw: null,
          proto: "DNP3",
          sec: null,
          life: null,
          ver: false,
          src: "vm-12-datasheet.pdf"
        },
        {
          id: "HMI-01",
          name: "Station HMI",
          mfr: null,
          model: null,
          fw: null,
          proto: "OPC UA",
          sec: null,
          life: null,
          ver: false,
          src: "manual entry"
        }
      ],
      ips: { "PLC-01": "10.30.1.10", "RTU-03": "10.30.1.22", "HMI-01": "10.30.1.50" },
      net: [
        dnpEvent(720, "RTU-03", "10.30.1.22", "Frames 40–96, 10.30.1.50 → 10.30.1.22:20000. Secure authentication was not checked."),
        {
          t: 29 * 60 + 50,
          asset: "PLC-01",
          title: "Modbus write (FC 6) from unlisted host 10.30.1.99",
          sev: "high",
          kind: "obs",
          rule: "R-MB-03: write function code from a source not in the allow-list",
          ev: "Frame 2290, 10:29:50, 10.30.1.99 → 10.30.1.10:502, FC 6, register 40008",
          src_ip: "10.30.1.99",
          verify: "Confirm 10.30.1.99 is an authorised engineering station and review the change ticket."
        }
      ],
      plc: [
        {
          t: 30 * 60 + 20,
          asset: "PLC-01",
          title: "Holding register 40008 changed; CPU mode stayed RUN",
          ev: "Audit record #305 (simulation export), user: unknown"
        }
      ],
      tel: genTelemetry(55, -55, 415, 3, 2),
      pv: { col: "voltage_v", n: "Busbar voltage", u: "V", lo: 0, hi: 1500 },
      rng: 20,
      st: 1,
      thr: { lo: 380, hi: 440 },
      allow: ["10.30.1.50"],
      fc: "FC 03 read ×360 · FC 06 write ×1"
    },
    {
      id: 4,
      name: "Plant D · Packaging Line",
      site: "Discrete manufacturing",
      assets: [
        {
          id: "PLC-01",
          name: "Packaging line controller",
          mfr: "Northwind Controls",
          model: "NC-250",
          fw: "V2.4.0",
          proto: "Modbus/TCP",
          ifc: "2 x Ethernet",
          sec: "Signed firmware, audit log",
          life: "Active product (datasheet statement)",
          ver: true,
          src: "nc-250-datasheet.pdf"
        },
        {
          id: "HMI-01",
          name: "Line HMI",
          mfr: "Northwind Controls",
          model: "NH-10",
          fw: "V1.2",
          proto: "Modbus/TCP",
          sec: null,
          life: null,
          ver: true,
          src: "nh-10-datasheet.pdf"
        }
      ],
      ips: { "PLC-01": "10.50.2.10", "HMI-01": "10.50.2.50" },
      net: [],
      plc: [],
      tel: genTelemetry(-1, 0, 62, 1.5, 3),
      pv: { col: "temperature_c", n: "Motor winding temperature", u: "°C", lo: -40, hi: 200 },
      rng: 10,
      st: 0.5,
      thr: { lo: 45, hi: 75 },
      allow: ["10.50.2.50"],
      fc: "FC 03 read ×360"
    }
  ];
};

