import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  BASE_T0,
  INITIAL_USERS,
  SCRIPT_EVENTS,
  createInitialPlants
} from "./data/initialData";
import { formatTime } from "./utils/helpers";
import { api, getAuthToken, clearAuthSession, setUnauthorizedHandler } from "./api/client";

import { Header } from "./components/Header";
import { Sidebar } from "./components/Sidebar";
import { GuidedTour } from "./components/GuidedTour";
import { LandingPage } from "./components/LandingPage";
import { LoginPage } from "./components/LoginPage";

import { FleetOverview } from "./views/FleetOverview";
import { PlantOverview } from "./views/PlantOverview";
import { LiveOperations } from "./views/LiveOperations";
import { AssetExplorer } from "./views/AssetExplorer";
import { NetworkAnalysis } from "./views/NetworkAnalysis";
import { ProcessAnalytics } from "./views/ProcessAnalytics";
import { CorrelationEngine } from "./views/CorrelationEngine";
import { ThreatIntelReports } from "./views/ThreatIntelReports";
import { RiskCompliance } from "./views/RiskCompliance";
import { ValidationSecurity } from "./views/ValidationSecurity";
import { DataSources } from "./views/DataSources";
import { Organization } from "./views/Organization";

const makeDefaultConnections = (ips) => {
  return Object.entries(ips)
    .filter(([a]) => /^(PLC|HMI)/.test(a))
    .map(([a, ip], k) => {
      const isPlc = a.startsWith("PLC");
      return {
        id: "C" + (k + 1),
        name: a + (isPlc ? " Modbus/TCP" : " OPC UA"),
        asset: a,
        proto: isPlc ? "Modbus/TCP" : "OPC UA",
        host: ip,
        port: isPlc ? 502 : 4840,
        mode: isPlc ? "Passive mirror (SPAN/TAP)" : "Read-only subscription",
        iv: 1,
        st: "down"
      };
    });
};

const getVerifyAction = (rule) => {
  if (!rule) return "Confirm the source is expected and review the change ticket.";
  if (rule.startsWith("R-MB-03")) return "Confirm the source is expected and review the change ticket.";
  if (rule.startsWith("R-PR-01")) return "Check whether this link crosses a trusted zone boundary.";
  if (rule.startsWith("R-AS-01")) return "Confirm the host is an authorised device and update the asset inventory.";
  if (rule.startsWith("R-PV-01")) return "Compare with historian data and check the instrument calibration.";
  return "Confirm the source is expected and review the change ticket.";
};

export default function App() {
  const [users, setUsers] = useState(INITIAL_USERS);
  const [currentUser, setCurrentUser] = useState(null);
  const [page, setPage] = useState("landing"); // "landing" | "login" | "app"
  const [currentView, setCurrentView] = useState("f");
  const [currentPlantIndex, setCurrentPlantIndex] = useState(0);

  const [plantsData, setPlantsData] = useState(() => createInitialPlants());
  const [org] = useState({ name: "Meridian Industries", plan: "Professional" });
  const [auditLog, setAuditLog] = useState([]);
  const [apiKeys, setApiKeys] = useState([]);
  const [notificationRules, setNotificationRules] = useState({
    critical: { email: true, slack: true },
    high: { email: true, slack: true },
    medium: { email: true, slack: false },
    low: { email: false, slack: false }
  });

  const [guideOn, setGuideOn] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);

  // Per-plant runtime states
  const [plantState, setPlantState] = useState(() => {
    const p0 = createInitialPlants()[0];
    return {
      assets: p0.assets.map((a) => ({ ...a })),
      ips: { ...p0.ips },
      net: p0.net.map((e) => ({ ...e })),
      plc: p0.plc.map((e) => ({ ...e })),
      tel: p0.tel.map((r) => ({ ...r })),
      t0: BASE_T0,
      telKind: "sim",
      netStats: null,
      thr: { ...p0.thr },
      confirmed: false,
      notes: "",
      windowSeconds: 120,
      selectedAssetId: null,
      searchQuery: "",
      draftAsset: null,
      connections: makeDefaultConnections(p0.ips),
      liveEvents: [],
      liveOn: true,
      liveK: 40,
      liveInj: 0,
      liveBuf: [...Array(40)].map((_, k) => {
        const g = p0.thr.hi - p0.thr.lo;
        const b = (p0.thr.lo + p0.thr.hi) / 2;
        return +(b + g * 0.06 * Math.sin((k + 1) / 5) + g * 0.02 * Math.sin((k + 1) * 1.7)).toFixed(2);
      }),
      lt: 0,
      lin: false
    };
  });

  const plantStateRef = useRef(plantState);
  plantStateRef.current = plantState;

  const currentPlantRef = useRef(currentPlantIndex);
  currentPlantRef.current = currentPlantIndex;

  const lidRef = useRef(0);

  const logAudit = useCallback((action, detail = "") => {
    setAuditLog((prev) => [
      {
        ts: new Date().toLocaleTimeString(),
        user: currentUser ? currentUser.u : "anonymous",
        a: action,
        d: detail
      },
      ...prev
    ]);
  }, [currentUser]);

  // Load a plant (updates state and fetches backend findings and assets if online)
  const loadPlant = useCallback(
    async (index, specificPlantId = null) => {
      const p = plantsData[index];
      if (!p) return;
      setCurrentPlantIndex(index);

      const targetPlantId = specificPlantId || p.id;
      const g = p.thr.hi - p.thr.lo;
      const b = (p.thr.lo + p.thr.hi) / 2;
      const initialBuf = [...Array(40)].map((_, k) => {
        return +(b + g * 0.06 * Math.sin((k + 1) / 5) + g * 0.02 * Math.sin((k + 1) * 1.7)).toFixed(2);
      });

      let netFindings = p.net.map((e) => ({ ...e }));
      let plantAssets = p.assets.map((a) => ({ ...a }));

      // Fetch real findings and assets from backend if authenticated
      if (getAuthToken()) {
        try {
          const dbFindings = await api.getFindings(targetPlantId);
          if (Array.isArray(dbFindings) && dbFindings.length > 0) {
            netFindings = dbFindings.map((f) => ({
              id: "F-00" + f.id,
              backendId: f.id,
              asset: f.asset || "PLC-01",
              title: f.title,
              sev: f.severity,
              kind: f.kind === "observed" ? "obs" : f.kind === "inferred" ? "inf" : "obs",
              ev: f.evidence,
              rule: f.rule,
              src_ip: f.src,
              verify: getVerifyAction(f.rule)
            }));
          }
        } catch {
          // If network error, retain baseline findings
        }

        try {
          const dbAssets = await api.getAssets(targetPlantId);
          if (Array.isArray(dbAssets) && dbAssets.length > 0) {
            plantAssets = dbAssets.map((a) => ({
              id: a.code,
              name: a.name,
              mfr: a.manufacturer || "Unknown",
              model: a.model || "Unknown",
              fw: a.firmware || null,
              proto: "Modbus/TCP",
              sec: "Active monitoring",
              life: "Active lifecycle",
              ver: Boolean(a.verified),
              src: "backend inventory"
            }));
          }
        } catch {
          // retain baseline assets
        }
      }

      setPlantState({
        assets: plantAssets,
        ips: { ...p.ips },
        net: netFindings,
        plc: p.plc.map((e) => ({ ...e })),
        tel: p.tel.map((r) => ({ ...r })),
        t0: BASE_T0,
        telKind: "sim",
        netStats: null,
        thr: { ...p.thr },
        confirmed: false,
        notes: "",
        windowSeconds: 120,
        selectedAssetId: null,
        searchQuery: "",
        draftAsset: null,
        connections: makeDefaultConnections(p.ips),
        liveEvents: [],
        liveOn: true,
        liveK: 40,
        liveInj: 0,
        liveBuf: initialBuf,
        lt: 0,
        lin: false
      });
    },
    [plantsData]
  );

  // Setup 401 unauthorized listener
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCurrentUser(null);
      setPage("login");
    });
  }, []);

  // Restore authenticated session on page reload
  useEffect(() => {
    const checkAuth = async () => {
      const token = getAuthToken();
      if (!token) return;

      try {
        const me = await api.getMe();
        const normalizedUser = {
          id: me.id,
          u: me.username,
          name: me.name,
          role: me.role === "company_admin" ? "Company admin" : "Plant user",
          rawRole: me.role,
          plants: me.plants || [1],
          status: "Active"
        };
        setCurrentUser(normalizedUser);

        const targetPlantId = me.plants[0] || 1;
        const pIdx = plantsData.findIndex((p) => p.id === targetPlantId);
        const safeIdx = pIdx >= 0 ? pIdx : 0;
        await loadPlant(safeIdx, targetPlantId);
        setCurrentView(me.role === "company_admin" ? "f" : "d");
        setPage("app");
      } catch {
        clearAuthSession();
      }
    };

    checkAuth();
  }, [loadPlant, plantsData]);

  const isAdmin = currentUser?.rawRole === "company_admin" || currentUser?.role === "Company admin";

  // Compute live value for rolling feed
  const computeLiveVal = useCallback((k, inj, plant) => {
    const g = plant.thr.hi - plant.thr.lo;
    const b = (plant.thr.lo + plant.thr.hi) / 2;
    return +(
      b +
      g * 0.06 * Math.sin(k / 5) +
      g * 0.02 * Math.sin(k * 1.7) +
      (inj > 0 ? Math.sin((Math.PI * (24 - inj)) / 24) * (g / 2 + g * 0.15) : 0)
    ).toFixed(2);
  }, []);

  // 1-second simulation timer
  useEffect(() => {
    const timer = setInterval(() => {
      const s = plantStateRef.current;
      const pi = currentPlantRef.current;
      const plant = plantsData[pi];
      if (!plant) return;

      let nextBuf = [...s.liveBuf];
      let nextK = s.liveK;
      let nextInj = s.liveInj;

      if (s.liveOn) {
        nextK++;
        const nextVal = computeLiveVal(nextK, nextInj, plant);
        if (nextInj > 0) nextInj--;
        nextBuf.push(nextVal);
        if (nextBuf.length > 60) {
          nextBuf.shift();
        }
      }

      // Check connections progress
      let connChanged = false;
      const nextConnections = s.connections.map((c) => {
        if (c.st === "connecting") {
          const step = (c.n || 0) + 1;
          if (step >= 2) {
            connChanged = true;
            return {
              ...c,
              st: "up",
              lat: 8 + Math.round(Math.random() * 14),
              n: step
            };
          }
          return { ...c, n: step };
        }
        return c;
      });

      const isAnyConnected = nextConnections.some((c) => c.st === "up");
      let nextLt = s.lt;
      let nextLiveEvents = [...s.liveEvents];
      let nextLin = s.lin;

      if (isAnyConnected) {
        nextLt++;
        const rel = 2700 + nextLt;
        const scriptEvents = SCRIPT_EVENTS[pi] || [];
        const matches = scriptEvents.filter((e) => e.at === nextLt);

        matches.forEach((e) => {
          lidRef.current++;
          nextLiveEvents.unshift({
            id: "L" + lidRef.current,
            cat: e.c,
            sev: e.sev,
            title: e.t,
            rule: e.r,
            asset: e.a,
            ip: e.ip,
            ev: e.e || `Source ${e.ip} seen talking to ${e.a} (${s.ips[e.a] || "unknown"})`,
            t: rel,
            ack: false,
            pr: false
          });
        });

        // Check if out of bounds
        const lastVal = nextBuf[nextBuf.length - 1];
        const isBad = lastVal > s.thr.hi || lastVal < s.thr.lo;

        if (isBad && !nextLin) {
          nextLin = true;
          lidRef.current++;
          nextLiveEvents.unshift({
            id: "L" + lidRef.current,
            cat: "Process",
            sev: "medium",
            title: `${plant.pv.n} ${lastVal.toFixed(2)} ${plant.pv.u} is outside ${s.thr.lo} to ${s.thr.hi}`,
            rule: "Limit check against the plant limits",
            asset: "PLC-01",
            ev: "Limits are set on the Process Analytics page",
            t: rel,
            ack: false
          });
        }
        if (!isBad) {
          nextLin = false;
        }
      }

      setPlantState((prev) => ({
        ...prev,
        liveK: nextK,
        liveInj: nextInj,
        liveBuf: nextBuf,
        connections: connChanged ? nextConnections : prev.connections,
        lt: nextLt,
        liveEvents: nextLiveEvents,
        lin: nextLin
      }));
    }, 1000);

    return () => clearInterval(timer);
  }, [computeLiveVal, plantsData]);

  // Current plant object
  const currentPlant = plantsData[currentPlantIndex] || plantsData[0];

  // Compute current findings
  const currentFindings = useMemo(() => {
    const f = [];
    const devs = plantState.tel.filter((r) => !r.miss && (r.p > plantState.thr.hi || r.p < plantState.thr.lo));
    const d0 = devs[0];
    const ptel = plantState.tel.filter((r) => !r.miss).map((r) => r.p);

    plantState.net.forEach((e) => {
      f.push({
        id: e.id || "F-00" + (f.length + 1),
        asset: e.asset,
        title: e.title,
        sev: e.sev,
        kind: e.kind,
        ev: e.ev,
        verify: e.verify || "Confirm the source is expected and review the change ticket.",
        rule: e.rule
      });
    });

    if (d0) {
      f.push({
        id: "F-00" + (f.length + 1),
        asset: "PLC-01",
        title: `${currentPlant.pv.n} outside ${plantState.thr.lo}–${plantState.thr.hi} ${currentPlant.pv.u} from ${formatTime(d0.t, plantState.t0)}`,
        sev: "medium",
        kind: plantState.telKind,
        ev: `${devs.length} samples outside ${plantState.thr.lo}–${plantState.thr.hi} ${currentPlant.pv.u}; observed range ${Math.min(...ptel)} to ${Math.max(...ptel)} ${currentPlant.pv.u}`,
        verify: "Compare with historian data and check the instrument calibration."
      });
    }

    if (d0 && plantState.net.some((e) => e.rule && e.rule.startsWith("R-MB-03"))) {
      f.push({
        id: "F-00" + (f.length + 1),
        asset: "PLC-01",
        title: "Write followed by pressure excursion",
        sev: "medium",
        kind: plantState.confirmed ? "conf" : "inf",
        ev: "A network write and a telemetry deviation are both present. Check the window on the Correlation page.",
        verify: "Inspect the register meaning and the operator log. Timing alone does not show cause."
      });
    }

    return f;
  }, [plantState, currentPlant]);

  // Summary per plant for fleet overview
  const plantSummaries = useMemo(() => {
    return plantsData.map((p, idx) => {
      if (idx === currentPlantIndex) {
        const countSev = (x) => currentFindings.filter((y) => y.sev === x).length;
        const risk = countSev("critical") * 5 + countSev("high") * 3 + countSev("medium") * 2 + countSev("low");
        const tot = plantState.assets.length || 1;
        const ver = plantState.assets.filter((a) => a.ver).length;
        const ul = plantState.liveEvents.filter((x) => x.cat === "Asset").length;
        const lc = plantState.liveEvents.filter((x) => x.cat === "Cyber" && !x.pr && !x.ack).length;

        const deductions = [
          Math.min(60, countSev("critical") * 20 + countSev("high") * 15 + countSev("medium") * 8 + countSev("low") * 3),
          Math.round((1 - ver / tot) * 15),
          Math.min(10, ul * 5),
          Math.min(10, lc * 5)
        ];
        const score = Math.max(0, 100 - deductions.reduce((a, b) => a + b, 0));

        return {
          n: currentFindings.length,
          h: countSev("high"),
          risk,
          score
        };
      } else {
        const fCount = p.net.length + (p.name.includes("Plant C") ? 1 : 0);
        const hCount = p.net.filter((x) => x.sev === "high").length;
        const risk = hCount * 3 + (fCount - hCount) * 2;
        const score = 85;
        return {
          n: fCount,
          h: hCount,
          risk,
          score
        };
      }
    });
  }, [plantsData, currentPlantIndex, currentFindings, plantState]);

  // Handlers
  const handleSignIn = async (username, password) => {
    // 1. Call real backend authentication
    await api.login(username, password);

    // 2. Fetch authenticated user profile & plant authorization
    const me = await api.getMe();
    const normalizedUser = {
      id: me.id,
      u: me.username,
      name: me.name,
      role: me.role === "company_admin" ? "Company admin" : "Plant user",
      rawRole: me.role,
      plants: me.plants || [1],
      status: "Active"
    };

    setCurrentUser(normalizedUser);
    logAudit("Sign in", normalizedUser.role);

    // 3. Load user's authorized plant
    const initialPlantId = normalizedUser.plants[0] || 1;
    const plantIdx = plantsData.findIndex((p) => p.id === initialPlantId);
    const safeIdx = plantIdx >= 0 ? plantIdx : 0;

    await loadPlant(safeIdx, initialPlantId);
    setCurrentView(normalizedUser.rawRole === "company_admin" ? "f" : "d");
    setGuideOn(false);
    setPage("app");
  };

  const handleSignOut = () => {
    logAudit("Sign out", "");
    clearAuthSession();
    setCurrentUser(null);
    setNotifOpen(false);
    setPage("login");
  };

  const handleSelectPlant = async (plantIdentifier) => {
    // plantIdentifier can be an index or plant id
    let targetPlant = plantsData.find((p) => p.id === plantIdentifier);
    let targetIndex = plantsData.findIndex((p) => p.id === plantIdentifier);

    if (!targetPlant && typeof plantIdentifier === "number" && plantsData[plantIdentifier]) {
      targetPlant = plantsData[plantIdentifier];
      targetIndex = plantIdentifier;
    }

    if (!targetPlant) return;

    if (currentUser && !currentUser.plants.includes(targetPlant.id)) {
      alert("Access Denied: You are not authorized to view this plant.");
      return;
    }

    await loadPlant(targetIndex, targetPlant.id);
    setCurrentView("d");
  };

  // PCAP upload to backend
  const handleUploadPcap = async (file) => {
    logAudit("Upload PCAP", file.name);
    const res = await api.uploadPcap(currentPlant.id, file);

    // Refresh findings from database
    try {
      const dbFindings = await api.getFindings(currentPlant.id);
      const mapped = dbFindings.map((f) => ({
        id: "F-00" + f.id,
        backendId: f.id,
        asset: f.asset || "PLC-01",
        title: f.title,
        sev: f.severity,
        kind: f.kind === "observed" ? "obs" : f.kind === "inferred" ? "inf" : "obs",
        ev: f.evidence,
        rule: f.rule,
        src_ip: f.src,
        verify: getVerifyAction(f.rule)
      }));

      setPlantState((prev) => ({
        ...prev,
        net: mapped
      }));
    } catch {
      // ignore
    }

    return res;
  };

  // Telemetry CSV upload to backend
  const handleUploadTelemetry = async (file, options) => {
    logAudit("Upload Telemetry CSV", file.name);
    const res = await api.uploadTelemetry(currentPlant.id, file, options);

    // Refresh findings in case an excursion finding (R-PV-01) was stored
    try {
      const dbFindings = await api.getFindings(currentPlant.id);
      const mapped = dbFindings.map((f) => ({
        id: "F-00" + f.id,
        backendId: f.id,
        asset: f.asset || "PLC-01",
        title: f.title,
        sev: f.severity,
        kind: f.kind === "observed" ? "obs" : f.kind === "inferred" ? "inf" : "obs",
        ev: f.evidence,
        rule: f.rule,
        src_ip: f.src,
        verify: getVerifyAction(f.rule)
      }));

      setPlantState((prev) => ({
        ...prev,
        net: mapped
      }));
    } catch {
      // ignore
    }

    return res;
  };

  // Report CSV export from backend
  const handleDownloadServerCsv = async () => {
    logAudit("Export CSV Report", `Plant ${currentPlant.id}`);
    const csvContent = await api.getReportCsv(currentPlant.id);
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ot-sentinel-plant-${currentPlant.id}-report.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleToggleConnection = (id) => {
    setPlantState((prev) => {
      const next = prev.connections.map((c) => {
        if (c.id === id) {
          if (c.st === "down") {
            logAudit("Connect source", c.name);
            return { ...c, st: "connecting", n: 0 };
          } else {
            logAudit("Disconnect source", c.name);
            return { ...c, st: "down" };
          }
        }
        return c;
      });
      return { ...prev, connections: next };
    });
  };

  const handleAddConnection = (newConn) => {
    lidRef.current++;
    setPlantState((prev) => ({
      ...prev,
      connections: [
        ...prev.connections,
        {
          id: "C" + lidRef.current + "x",
          ...newConn,
          st: "down"
        }
      ]
    }));
  };

  const handleAcknowledgeLiveEvent = (eventId) => {
    setPlantState((prev) => {
      const target = prev.liveEvents.find((x) => x.id === eventId);
      if (target) {
        logAudit("Acknowledge event", target.title);
      }
      return {
        ...prev,
        liveEvents: prev.liveEvents.map((x) => (x.id === eventId ? { ...x, ack: true } : x))
      };
    });
  };

  const handleAddLiveEventToReport = (event) => {
    logAudit("Add event to report", event.title);
    setPlantState((prev) => ({
      ...prev,
      liveEvents: prev.liveEvents.map((x) => (x.id === event.id ? { ...x, pr: true } : x)),
      net: [
        ...prev.net,
        {
          t: event.t,
          asset: event.asset,
          title: event.title,
          sev: event.sev,
          kind: "obs",
          rule: event.rule,
          ev: event.ev,
          src_ip: event.ip,
          verify: "Confirm the source is expected and review the change ticket."
        }
      ]
    }));
  };

  const handleDraftUnlistedAsset = (ip) => {
    let n = plantState.assets.length + 1;
    const format = (num) => `AST-${String(num).padStart(2, "0")}`;
    while (plantState.assets.some((a) => a.id === format(n))) n++;

    setPlantState((prev) => ({
      ...prev,
      draftAsset: {
        id: format(n),
        name: "Unlisted device " + ip,
        proto: "Modbus/TCP",
        src: "live discovery " + ip
      }
    }));
    setCurrentView("a");
  };

  const handleSaveAsset = async (newAsset) => {
    logAudit("Add asset", newAsset.id);

    if (getAuthToken()) {
      try {
        await api.addAsset(currentPlant.id, {
          code: newAsset.id,
          name: newAsset.name,
          ip: newAsset.ip || null,
          manufacturer: newAsset.mfr || null,
          model: newAsset.model || null,
          firmware: newAsset.fw || null
        });
      } catch (err) {
        console.warn("Backend addAsset:", err.message);
      }
    }

    setPlantState((prev) => ({
      ...prev,
      assets: [...prev.assets, newAsset],
      selectedAssetId: newAsset.id,
      draftAsset: null,
      searchQuery: ""
    }));

    setPlantsData((prevPlants) => {
      const copy = [...prevPlants];
      copy[currentPlantIndex] = {
        ...copy[currentPlantIndex],
        assets: [...copy[currentPlantIndex].assets, newAsset]
      };
      return copy;
    });
  };

  const handlePcapAnalyzed = (events, netStats) => {
    setPlantState((prev) => ({
      ...prev,
      net: events,
      netStats
    }));
  };

  const handleTelemetryAnalyzed = (newTel, newT0, newKind) => {
    setPlantState((prev) => ({
      ...prev,
      tel: newTel,
      t0: newT0,
      telKind: newKind
    }));
  };

  const handleToggleUserStatus = (u) => {
    setUsers((prev) =>
      prev.map((user) => {
        if (user.u === u) {
          const newStatus = user.status === "Disabled" ? "Active" : "Disabled";
          logAudit(newStatus === "Disabled" ? "Disable user" : "Enable user", user.u);
          return { ...user, status: newStatus };
        }
        return user;
      })
    );
  };

  const handleInviteUser = (newUser) => {
    logAudit("Invite user", `${newUser.u} as ${newUser.role}`);
    setUsers((prev) => [...prev, newUser]);
  };

  const handleChangeNotificationRule = (sev, channel, checked) => {
    logAudit("Change notification rule", `${sev} via ${channel}: ${checked ? "on" : "off"}`);
    setNotificationRules((prev) => ({
      ...prev,
      [sev]: {
        ...prev[sev],
        [channel]: checked
      }
    }));
  };

  const handleCreateApiKey = () => {
    const a = new Uint8Array(16);
    crypto.getRandomValues(a);
    const k = "otk_demo_" + [...a].map((x) => x.toString(16).padStart(2, "0")).join("");
    const newKey = {
      id: k.slice(-6),
      k,
      at: new Date().toLocaleString(),
      isNew: true
    };
    logAudit("Create API key", "Read-only, ending " + k.slice(-6));
    setApiKeys((prev) => [newKey, ...prev.map((item) => ({ ...item, isNew: false }))]);
  };

  const handleRevokeApiKey = (id) => {
    logAudit("Revoke API key", "ending " + id);
    setApiKeys((prev) => prev.filter((x) => x.id !== id));
  };

  // Render view router
  const renderCurrentView = () => {
    switch (currentView) {
      case "f":
        return isAdmin ? (
          <FleetOverview
            plants={plantsData}
            plantSummaries={plantSummaries}
            onSelectPlant={handleSelectPlant}
            onNavigate={(v) => setCurrentView(v)}
            audit={auditLog}
            users={users}
          />
        ) : (
          <PlantOverview
            plant={currentPlant}
            assets={plantState.assets}
            findings={currentFindings}
            netEvents={plantState.net}
            telemetry={plantState.tel}
            telemetryKind={plantState.telKind}
            thresholds={plantState.thr}
            confirmed={plantState.confirmed}
            liveBuffer={plantState.liveBuf}
            liveOn={plantState.liveOn}
            onToggleLive={() => setPlantState((p) => ({ ...p, liveOn: !p.liveOn }))}
            onSimulateExcursion={() => setPlantState((p) => ({ ...p, liveInj: 24 }))}
            t0={plantState.t0}
          />
        );

      case "d":
        return (
          <PlantOverview
            plant={currentPlant}
            assets={plantState.assets}
            findings={currentFindings}
            netEvents={plantState.net}
            telemetry={plantState.tel}
            telemetryKind={plantState.telKind}
            thresholds={plantState.thr}
            confirmed={plantState.confirmed}
            liveBuffer={plantState.liveBuf}
            liveOn={plantState.liveOn}
            onToggleLive={() => setPlantState((p) => ({ ...p, liveOn: !p.liveOn }))}
            onSimulateExcursion={() => setPlantState((p) => ({ ...p, liveInj: 24 }))}
            t0={plantState.t0}
          />
        );

      case "l":
        return (
          <LiveOperations
            plant={currentPlant}
            assets={plantState.assets}
            ips={plantState.ips}
            connections={plantState.connections}
            onToggleConnection={handleToggleConnection}
            onAddConnection={handleAddConnection}
            liveBuffer={plantState.liveBuf}
            liveK={plantState.liveK}
            liveEvents={plantState.liveEvents}
            onAcknowledgeEvent={handleAcknowledgeLiveEvent}
            onAddEventToReport={handleAddLiveEventToReport}
            onDraftUnlistedAsset={handleDraftUnlistedAsset}
            onSimulateExcursion={() => setPlantState((p) => ({ ...p, liveInj: 24 }))}
            thresholds={plantState.thr}
            t0={plantState.t0}
          />
        );

      case "a":
        return (
          <AssetExplorer
            assets={plantState.assets}
            onSaveAsset={handleSaveAsset}
            selectedAssetId={plantState.selectedAssetId}
            onSelectAsset={(id) => setPlantState((p) => ({ ...p, selectedAssetId: id }))}
            draft={plantState.draftAsset}
            setDraft={(d) => setPlantState((p) => ({ ...p, draftAsset: d }))}
            searchQuery={plantState.searchQuery}
            setSearchQuery={(q) => setPlantState((p) => ({ ...p, searchQuery: q }))}
          />
        );

      case "n":
        return (
          <NetworkAnalysis
            plant={currentPlant}
            ips={plantState.ips}
            netEvents={plantState.net}
            netStats={plantState.netStats}
            onPcapAnalyzed={handlePcapAnalyzed}
            onUploadPcap={handleUploadPcap}
            t0={plantState.t0}
          />
        );

      case "p":
        return (
          <ProcessAnalytics
            plant={currentPlant}
            telemetry={plantState.tel}
            telemetryKind={plantState.telKind}
            thresholds={plantState.thr}
            onThresholdsChange={(newThr) => setPlantState((p) => ({ ...p, thr: newThr }))}
            onTelemetryAnalyzed={handleTelemetryAnalyzed}
            onUploadTelemetry={handleUploadTelemetry}
            t0={plantState.t0}
          />
        );

      case "c":
        return (
          <CorrelationEngine
            plant={currentPlant}
            netEvents={plantState.net}
            plcEvents={plantState.plc}
            telemetry={plantState.tel}
            telemetryKind={plantState.telKind}
            thresholds={plantState.thr}
            windowSeconds={plantState.windowSeconds}
            onWindowChange={(win) => setPlantState((p) => ({ ...p, windowSeconds: win }))}
            notes={plantState.notes}
            onNotesChange={(notes) => setPlantState((p) => ({ ...p, notes }))}
            confirmed={plantState.confirmed}
            onToggleConfirmed={() => setPlantState((p) => ({ ...p, confirmed: !p.confirmed }))}
            t0={plantState.t0}
          />
        );

      case "t":
        return (
          <ThreatIntelReports
            findings={currentFindings}
            onDownloadServerCsv={handleDownloadServerCsv}
          />
        );

      case "r":
        return (
          <RiskCompliance
            plant={currentPlant}
            assets={plantState.assets}
            findings={currentFindings}
            liveEvents={plantState.liveEvents}
            connections={plantState.connections}
            thresholds={plantState.thr}
          />
        );

      case "v":
        return <ValidationSecurity />;

      case "s":
        return <DataSources />;

      case "o":
        return isAdmin ? (
          <Organization
            org={org}
            plants={plantsData}
            users={users}
            onToggleUserStatus={handleToggleUserStatus}
            onInviteUser={handleInviteUser}
            notificationRules={notificationRules}
            onChangeNotificationRule={handleChangeNotificationRule}
            apiKeys={apiKeys}
            onCreateApiKey={handleCreateApiKey}
            onRevokeApiKey={handleRevokeApiKey}
            auditLog={auditLog}
            currentUser={currentUser}
          />
        ) : null;

      default:
        return null;
    }
  };

  if (page === "landing") {
    return <LandingPage plants={plantsData} onGoToLogin={() => setPage("login")} />;
  }

  if (page === "login") {
    return (
      <LoginPage
        users={users}
        onSignIn={handleSignIn}
        onBackToHome={() => setPage("landing")}
        onLogAudit={logAudit}
      />
    );
  }

  return (
    <div className="app" id="app">
      <Sidebar
        currentView={currentView}
        onSelectView={(k) => setCurrentView(k)}
        isAdmin={isAdmin}
        org={org}
      />

      <main>
        <Header
          plants={plantsData}
          currentPlantId={currentPlant.id}
          onPlantChange={handleSelectPlant}
          user={currentUser}
          guideOn={guideOn}
          setGuideOn={setGuideOn}
          notifOpen={notifOpen}
          setNotifOpen={setNotifOpen}
          onSignOut={handleSignOut}
          openFindingsCount={currentFindings.length}
          liveEvents={plantState.liveEvents}
          findings={currentFindings}
          t0={plantState.t0}
        />

        <div className="content" id="view">
          {guideOn && (
            <GuidedTour
              onClose={() => setGuideOn(false)}
              onNavigate={(k) => setCurrentView(k)}
              isAdmin={isAdmin}
            />
          )}

          <div className="view">
            {currentView !== "f" && currentView !== "s" && currentView !== "o" && currentView !== "v" && (
              <div className="sub" style={{ margin: "0 0 6px", fontSize: "12px" }}>
                {currentPlant.name}
              </div>
            )}

            {renderCurrentView()}

            <div className="sub" style={{ marginTop: "32px", fontSize: "12px", borderTop: "1px solid var(--line)", paddingTop: "12px" }}>
              OT Sentinel prototype · Read-only by design · Simulation data
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
