"""Measures the detection and correlation code on generated, labeled scenarios.
These are deterministic rules, so the numbers show the code does what the rules say and how it behaves on awkward input.
They do NOT measure accuracy on real plant traffic. Run: python validate.py"""
import json, random, statistics
from app.detection import analyze_series, correlate, detect, parse_pcap
from app.pcapgen import build_pcap, frame, modbus

CFG = {"assets": {"10.0.0.10": "PLC-01", "10.0.0.21": "RTU-04"}, "allow": ["10.0.0.50", "10.0.0.30"]}
RULES = ["R-MB-03", "R-AS-01", "R-PR-01"]
rng = random.Random(42)

def poll(n=20):
    return [(i * 10.0, frame("10.0.0.50", "10.0.0.10", 49152, 502, modbus(i + 1, 3, 0, b"\x00\x04"))) for i in range(n)]

def scen(kind):
    pk, exp, kw = poll(rng.randint(5, 40)), set(), {}
    src = f"10.0.1.{rng.randint(60, 200)}"; fc = rng.choice([5, 6, 15, 16]); t = rng.uniform(1, 150)
    if kind == "benign": pass
    elif kind == "allowed_write": pk.append((t, frame(rng.choice(CFG["allow"]), "10.0.0.10", 50000, 502, modbus(9, fc, rng.randint(0, 100), b"\x00\x01"))))
    elif kind == "unlisted_write": pk.append((t, frame(src, "10.0.0.10", 50000, 502, modbus(9, fc, rng.randint(0, 100), b"\x00\x01"), vlan=rng.random() < .2))); exp = {"R-MB-03", "R-AS-01"}
    elif kind == "unlisted_read": pk.append((t, frame(src, "10.0.0.10", 50000, 502, modbus(9, rng.choice([3, 4]), 0, b"\x00\x02")))); exp = {"R-AS-01"}
    elif kind == "dnp3_cleartext": pk.append((t, frame("10.0.0.50", "10.0.0.21", 50410, 20000, bytes([5, 0x64, 5, 0xC0, 1, 0])))); exp = {"R-PR-01"}
    elif kind == "write_response_direction": pk.append((t, frame("10.0.0.10", "10.0.0.50", 502, 50000, modbus(9, 16, 20))))
    elif kind == "write_on_other_port": pk.append((t, frame(src, "10.0.0.10", 50000, 5020, modbus(9, 16, 20, b"\x00\x01"))))
    elif kind == "non_modbus_payload_on_502": pk.append((t, frame(src, "10.0.0.10", 50000, 502, b"GET / HTTP/1.1\r\n\r\n"))); exp = {"R-AS-01"}
    elif kind == "truncated_capture": kw["truncate_last"] = rng.randint(1, 30)
    elif kind == "retransmitted_write": f = frame(src, "10.0.0.10", 50000, 502, modbus(9, fc, 5, b"\x00\x01")); pk += [(t, f), (t + 1, f)]; exp = {"R-MB-03", "R-AS-01"}
    return build_pcap(pk, big_endian=rng.random() < .2, **kw), exp

KINDS = ["benign", "allowed_write", "unlisted_write", "unlisted_read", "dnp3_cleartext", "write_response_direction",
         "write_on_other_port", "non_modbus_payload_on_502", "truncated_capture", "retransmitted_write"]
N = 40
cm = {r: dict(tp=0, fp=0, fn=0, tn=0) for r in RULES}; per = {}; crashes = 0; extra_dupes = 0
for k in KINDS:
    ok = 0
    for _ in range(N):
        data, exp = scen(k)
        try:
            ev = detect(parse_pcap(data)[0], CFG)
        except Exception:
            crashes += 1; continue
        got = {e["rule"] for e in ev}
        extra_dupes += (sum(e["rule"] == "R-MB-03" for e in ev) > 1) if k == "retransmitted_write" else 0
        ok += (got & set(RULES)) == exp
        for r in RULES:
            key = ("tp" if r in got else "fn") if r in exp else ("fp" if r in got else "tn")
            cm[r][key] += 1
    per[k] = round(ok / N * 100, 1)
net = {}
for r, c in cm.items():
    net[r] = dict(**c, precision=round(c["tp"] / (c["tp"] + c["fp"]), 3) if c["tp"] + c["fp"] else None,
                  recall=round(c["tp"] / (c["tp"] + c["fn"]), 3) if c["tp"] + c["fn"] else None)

# telemetry: injected excursions against fixed limits, and false alarms on clean noisy series
def series(sd, peak=0.0, n=120):
    base, v = 6.2, []
    for i in range(n):
        x = base + rng.gauss(0, sd)
        if peak and 60 <= i <= 72: x += peak * (1 - abs(i - 66) / 6)
        v.append((i * 30.0, round(x, 3)))
    return v
LO, HI, T = 5.0, 7.5, 200
tel = []
for peak in (0.5, 1.0, 1.5, 2.0, 3.0):
    det = truth = 0
    for _ in range(T):
        s = series(0.1, peak); truth += any(v > HI for _, v in s); det += analyze_series(s, LO, HI)["deviations"] > 0
    tel.append(dict(peak_above_baseline=peak, series_exceeding_limit=round(truth / T * 100, 1), detected=round(det / T * 100, 1)))
fa = [dict(noise_sd=sd, false_alarm_series_pct=round(sum(analyze_series(series(sd), LO, HI)["deviations"] > 0 for _ in range(T)) / T * 100, 1)) for sd in (0.1, 0.3, 0.5, 0.7)]

# correlation: planted chain vs unrelated coincidences, across window sizes
def corr_trial(window, planted):
    t0 = rng.uniform(600, 3000); dev = t0 + rng.uniform(20, 120)
    net_e = [dict(ts=rng.uniform(0, 3600), asset="PLC-01", tag="noise") for _ in range(3)]
    aud_e = [dict(ts=rng.uniform(0, 3600), asset="PLC-01", tag="noise") for _ in range(3)]
    if planted: net_e.append(dict(ts=t0, asset="PLC-01", tag="true")); aud_e.append(dict(ts=t0 + rng.uniform(10, 60), asset="PLC-01", tag="true"))
    return correlate(net_e, aud_e, dev, window, "PLC-01")
cor = []
for w in (30, 60, 120, 300, 600):
    rec = prec_t = prec_all = false_link = 0
    for _ in range(T):
        r = corr_trial(w, True); tags = [e["tag"] for e in r["linked"]]
        rec += tags.count("true") == 2; prec_t += tags.count("true"); prec_all += len(tags)
        false_link += corr_trial(w, False)["confidence"] != "none"
    cor.append(dict(window_s=w, planted_chain_found_pct=round(rec / T * 100, 1), linked_events_that_are_true_pct=round(prec_t / prec_all * 100, 1) if prec_all else None,
                    unrelated_scenarios_linked_pct=round(false_link / T * 100, 1)))
out = dict(network=net, scenario_pass_rate_pct=per, scenarios_per_kind=N, crashes=crashes, duplicate_findings_on_retransmit=extra_dupes, telemetry_detection=tel, telemetry_false_alarms=fa, correlation=cor)
json.dump(out, open("validation_report.json", "w"), indent=2)
print(json.dumps(out, indent=1))
