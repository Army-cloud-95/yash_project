"""Generates the 5 SYNTHETIC OT Sentinel demo datasets. No real devices or networks involved."""
import csv, json, math, struct, socket, datetime as dt, os
OUT = os.path.dirname(os.path.abspath(__file__))
T0 = dt.datetime(2026, 10, 14, 10, 0, 0, tzinfo=dt.timezone.utc)
iso = lambda s: (T0 + dt.timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%SZ")

# 1. Telemetry CSV (Process Analytics)
with open(f"{OUT}/02_telemetry_plc01.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp","asset_id","pressure_bar","temperature_c","voltage_v","current_a","motor_state","valve_state","data_label"])
    for i in range(120):
        p = 6.2 + .25*math.sin(i/6) + .08*math.sin(i*2.3)
        if 84 <= i <= 96: p += (i-83)/12*2.2
        if 96 < i <= 108: p += (108-i)/12*2.2
        miss = i in (31, 32)
        w.writerow([iso(i*30), "PLC-01", "" if miss else f"{p:.2f}", f"{71+1.8*math.sin(i/9):.1f}",
                    f"{400+3*math.sin(i/5):.0f}", f"{12.5+.6*math.sin(i/7):.1f}", "ON", "OPEN" if i >= 84 else "CLOSED", "SYNTHETIC"])

# 2. PLC audit events CSV (Correlation Engine)
audit = [
 (5,"A-0901","engineer.demo","LOGIN","session","","","RUN","engineering-ws 10.20.4.30"),
 (900,"A-0907","engineer.demo","LOGOUT","session","","","RUN","engineering-ws 10.20.4.30"),
 (41*60+40,"A-0918","unknown","REGISTER_WRITE","holding_register_40021","5800","7900","RUN","network 10.20.4.77"),
 (44*60+5,"A-0921","operator.demo","ALARM_ACK","high_pressure_alarm","","","RUN","hmi 10.20.4.50"),
]
with open(f"{OUT}/04_plc_audit_events.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp","asset_id","event_id","user","action","object","old_value","new_value","cpu_mode","source","data_label"])
    for s,e,u,a,o,ov,nv,m,src in audit:
        w.writerow([iso(s),"PLC-01",e,u,a,o,ov,nv,m,src,"SYNTHETIC"])

# 3. PCAP (Network Analysis) - hand-built Ethernet/IPv4/TCP frames, offline file only
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
def frame(src, dst, sp, dp, seq, ack, flags, payload):
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 8192, 0, 0)
    pseudo = s + d + struct.pack("!BBH", 0, 6, len(tcp)+len(payload))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(tcp)+len(payload), 1, 0, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    mac = lambda x: bytes([2,0,0,0,0,int(x.split(".")[-1])])
    return mac(dst) + mac(src) + b"\x08\x00" + ip + tcp + payload
HMI, PLC, ENG, RTU = "10.20.4.50", "10.20.4.10", "10.20.4.77", "10.20.4.21"
pk = []
def add(ts, *a): pk.append((ts, frame(*a)))
tid = 0
for k in range(360):                       # FC03 polling every 10 s for one hour
    t = k*10.0; tid += 1
    req = struct.pack("!HHHBBHH", tid, 0, 6, 1, 3, 0, 4)
    rsp = struct.pack("!HHHBBB", tid, 0, 3+8, 1, 3, 8) + struct.pack("!4H", 620, 71, 400, 125)
    add(t, HMI, PLC, 49152, 502, 1000+k*12, 5000+k*17, 0x18, req)
    add(t+.01, PLC, HMI, 502, 49152, 5000+k*17, 1000+(k+1)*12, 0x18, rsp)
t = 41*60+12.0                            # FC16 write from a host not on the allow-list
req = struct.pack("!HHHBBHHB", 7001, 0, 11, 1, 16, 20, 2, 4) + struct.pack("!2H", 0, 7900)
rsp = struct.pack("!HHHBBHH", 7001, 0, 6, 1, 16, 20, 2)
add(t, ENG, PLC, 50321, 502, 9000, 7000, 0x18, req); add(t+.02, PLC, ENG, 502, 50321, 7000, 9000+len(req), 0x18, rsp)
for k in range(6):                        # cleartext DNP3 (starts 0x0564) HMI -> RTU
    add(5*60+20+k*2.0, HMI, RTU, 50410, 20000, 3000+k*10, 4000, 0x18, bytes([0x05,0x64,0x05,0xC0,0x01,0x00,0x00,0x04,0x00,0x00]))
pk.sort(key=lambda x: x[0])
base = int(T0.timestamp())
with open(f"{OUT}/03_plant_a_sample.pcap", "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, fr in pk:
        f.write(struct.pack("<IIII", base+int(ts), int((ts % 1)*1e6), len(fr), len(fr)) + fr)

# 5. Seed config (assets, allow-list, thresholds, correlation rules, ATT&CK mappings)
cfg = {"data_label":"SYNTHETIC","workspace":"Demo workspace",
 "assets":[{"id":"PLC-01","name":"Boiler line controller","ip":PLC,"manufacturer":"Northwind Controls (fictional)","model":"NC-400","firmware":"V3.2.1","verified":True},
           {"id":"RTU-04","name":"Remote pump RTU","ip":RTU,"manufacturer":None,"model":None,"firmware":None,"verified":False},
           {"id":"HMI-02","name":"Operator panel","ip":HMI,"manufacturer":None,"model":None,"firmware":None,"verified":False}],
 "modbus_write_allowlist":[HMI,"10.20.4.30"],
 "thresholds":{"PLC-01":{"pressure_bar":{"min":5.0,"max":7.5},"temperature_c":{"min":60,"max":85}}},
 "correlation":{"window_seconds":120,"match_on":["asset_id","time_window"],"note":"Temporal proximity does not prove causation."},
 "attack_ics_mappings":[{"rule":"R-MB-03","technique":"T0836","name":"Modify Parameter","min_evidence":"packet capture + write FC"}]}
json.dump(cfg, open(f"{OUT}/05_seed_config.json","w"), indent=2)
print("ok", len(pk), "packets")
