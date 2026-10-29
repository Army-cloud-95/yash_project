"""Offline analysis: PCAP parsing, rule-based detections, telemetry statistics, correlation.
Pure functions, no network access, nothing is ever sent to a device."""
import csv, io, statistics, struct
from datetime import datetime

IND_PORTS = {502: "Modbus/TCP", 20000: "DNP3", 102: "S7Comm", 4840: "OPC UA", 44818: "EtherNet/IP"}
WRITE_FC = {5, 6, 15, 16}
DIAG_FC = {8}
MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
          b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}

MITRE_ICS = {
    "R-MB-03": ("T0855", "Unauthorized Command Message"),
    "R-AS-01": ("T0846", "Remote System Discovery"),
    "R-PR-01": ("T0807", "Command and Control / Unencrypted Protocol"),
    "R-PV-01": ("T0836", "Modify Parameter / Process Deviation"),
    "R-MB-04": ("T0887", "Reconnaissance - Exception Code Scan"),
    "R-MB-05": ("T0815", "Denial of Control - Diagnostic Command"),
    "R-AU-01": ("T0858", "Change Operating Mode / Parameter Tampering"),
}

def _ip(b): return ".".join(str(x) for x in b)

def _tcp(f):
    if len(f) < 34: return None
    et, off = struct.unpack("!H", f[12:14])[0], 14
    if et == 0x8100 and len(f) >= 18: et, off = struct.unpack("!H", f[16:18])[0], 18
    if et != 0x0800 or len(f) < off + 20: return None
    ihl = (f[off] & 15) * 4
    if ihl < 20 or f[off + 9] != 6 or len(f) < off + ihl + 20: return None
    t = off + ihl
    doff = (f[t + 12] >> 4) * 4
    if doff < 20: return None
    return {"src": _ip(f[off + 12:off + 16]), "dst": _ip(f[off + 16:off + 20]),
            "sport": struct.unpack("!H", f[t:t + 2])[0], "dport": struct.unpack("!H", f[t + 2:t + 4])[0],
            "payload": bytes(f[t + doff:t + doff + 64])}

def parse_pcap(data: bytes, max_packets: int = 200_000):
    if len(data) < 24: raise ValueError("file is too short to be a pcap")
    m = MAGICS.get(bytes(data[:4]))
    if not m: raise ValueError("not a classic pcap file (pcapng is not supported)")
    e, res = m
    if struct.unpack(e + "I", data[20:24])[0] != 1: raise ValueError("only Ethernet captures are supported")
    out, o, n = [], 24, 0
    while o + 16 <= len(data) and n < max_packets:
        sec, frac, incl, _ = struct.unpack(e + "IIII", data[o:o + 16])
        p, o, n = o + 16, o + 16 + incl, n + 1
        if incl > 65535 or o > len(data): break
        pk = _tcp(data[p:p + incl])
        if pk: pk.update(n=n, ts=sec + frac / res); out.append(pk)
    return out, n

def _with_mitre(ev_dict):
    m_id, m_name = MITRE_ICS.get(ev_dict["rule"], ("T0800", "ICS Attack"))
    ev_dict.setdefault("mitre_id", m_id)
    ev_dict.setdefault("mitre_name", m_name)
    return ev_dict

def detect(packets, cfg):
    """cfg: {"assets": {ip: asset_code}, "allow": [ips allowed to send writes]}. Returns a list of events."""
    assets, allow = cfg["assets"], set(cfg.get("allow", []))
    known, ev, seen, unl, dnp = set(assets) | allow, [], set(), {}, {}
    for p in packets:
        pl, dst = p["payload"], p["dst"]
        if p["dport"] == 502 and len(pl) >= 8 and pl[2:4] == b"\x00\x00" and pl[7] in WRITE_FC and p["src"] not in allow:
            reg = struct.unpack("!H", pl[8:10])[0] + 40001 if len(pl) >= 10 else None
            k = (p["src"], dst, pl[7], reg)
            if k not in seen:
                seen.add(k)
                ev.append(_with_mitre(dict(rule="R-MB-03", sev="high", asset=assets.get(dst, "Unmapped"), src=p["src"], dst=dst, ts=p["ts"], frame=p["n"],
                    title=f"Modbus write (FC {pl[7]}) from unlisted host {p['src']}",
                    evidence=f"Frame {p['n']}, {p['src']} → {dst}:502, FC {pl[7]}, register {reg}")))
        if p["dport"] in IND_PORTS and p["src"] not in known and p["src"] not in unl: unl[p["src"]] = p
        if p["dport"] == 20000 and pl[:2] == b"\x05\x64" and (p["src"], dst) not in dnp: dnp[(p["src"], dst)] = p
    for src, p in unl.items():
        ev.append(_with_mitre(dict(rule="R-AS-01", sev="medium", asset=assets.get(p["dst"], "Unmapped"), src=src, dst=p["dst"], ts=p["ts"], frame=p["n"],
            title=f"Unlisted host {src} seen on {IND_PORTS[p['dport']]}", evidence=f"Frame {p['n']}, {src} → {p['dst']}:{p['dport']}")))
    for (src, d), p in dnp.items():
        ev.append(_with_mitre(dict(rule="R-PR-01", sev="low", asset=assets.get(d, "Unmapped"), src=src, dst=d, ts=p["ts"], frame=p["n"],
            title=f"Cleartext DNP3 traffic to {d}", evidence=f"Frame {p['n']}, {src} → {d}:20000. Secure authentication was not checked.")))
    return sorted(ev, key=lambda x: x["ts"])

REQUIRED = ["timestamp", "pressure_bar", "temperature_c", "voltage_v", "current_a", "motor_state", "valve_state"]

def parse_telemetry(text: str, col: str, lo_ok: float, hi_ok: float, max_rows: int = 20000):
    rd = csv.DictReader(io.StringIO(text))
    head = [h.strip().lower() for h in (rd.fieldnames or [])]
    gap = [c for c in REQUIRED if c not in head]
    if gap: raise ValueError("missing columns: " + ", ".join(gap))
    rd.fieldnames, rows, t0 = head, [], None
    for i, r in enumerate(rd, start=2):
        if i - 1 > max_rows: raise ValueError(f"more than {max_rows} rows")
        try: ts = datetime.fromisoformat(r["timestamp"].strip().replace("Z", "+00:00")).timestamp()
        except ValueError: raise ValueError(f"row {i}: invalid timestamp")
        t0 = ts if t0 is None else t0
        raw = (r[col] or "").strip()
        if raw == "": rows.append((ts, None)); continue
        try: v = float(raw)
        except ValueError: raise ValueError(f"row {i}: {col} is not a number")
        if not lo_ok <= v <= hi_ok: raise ValueError(f"row {i}: {col} {v} is outside {lo_ok} to {hi_ok}. Check the unit.")
        rows.append((ts, v))
    if sum(v is not None for _, v in rows) < 2: raise ValueError("fewer than 2 rows have a value")
    return rows

def analyze_series(rows, lo, hi):
    vals = [v for _, v in rows if v is not None]
    m, sd = statistics.fmean(vals), statistics.stdev(vals)
    dev = [t for t, v in rows if v is not None and (v > hi or v < lo)]
    return dict(n=len(rows), missing=len(rows) - len(vals), mean=m, median=statistics.median(vals), std=sd,
                cv=sd / m * 100 if m else None, deviations=len(dev), first_deviation=dev[0] if dev else None)

def parse_plc_audit(text: str, max_rows: int = 10000):
    """Parses PLC host audit CSV file (timestamp, asset_id, event_id, action, object, etc.)."""
    rd = csv.DictReader(io.StringIO(text))
    head = [h.strip().lower() for h in (rd.fieldnames or [])]
    for req in ("timestamp", "asset_id", "action"):
        if req not in head: raise ValueError(f"missing required audit column: {req}")
    events = []
    for i, r in enumerate(rd, start=2):
        if i - 1 > max_rows: break
        try: ts = datetime.fromisoformat(r["timestamp"].strip().replace("Z", "+00:00")).timestamp()
        except (ValueError, KeyError, AttributeError): continue
        events.append(dict(
            ts=ts,
            asset=r.get("asset_id", "").strip(),
            event_id=r.get("event_id", "").strip(),
            user=r.get("user", "").strip(),
            action=r.get("action", "").strip(),
            object=r.get("object", "").strip(),
            old_value=r.get("old_value", "").strip(),
            new_value=r.get("new_value", "").strip(),
            cpu_mode=r.get("cpu_mode", "").strip(),
            source=r.get("source", "").strip()
        ))
    return events

def correlate(net, audit, dev_ts, window, asset):
    """net/audit: dicts with ts and asset. Links events on the same asset within +/- window of the first deviation.
    Confidence describes how many independent sources agree in time. It never claims causation."""
    if dev_ts is None: return dict(linked=[], confidence="none", note="No process deviation to correlate.")
    pick = lambda L, src: [dict(e, source=src) for e in L if e.get("asset") in (asset, None) and abs(e["ts"] - dev_ts) <= window]
    n, a = pick(net, "network"), pick(audit, "audit")
    conf = "moderate" if n and a else "low" if n or a else "none"
    return dict(linked=sorted(n + a, key=lambda e: e["ts"]), confidence=conf,
                note="Events are close in time. This does not show that one caused the other.")
