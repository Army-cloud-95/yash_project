"""Builds small classic-pcap files (Ethernet/IPv4/TCP) for tests and validation."""
import socket, struct

def _csum(b: bytes) -> int:
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def frame(src, dst, sp, dp, payload=b"", flags=0x18, seq=1, ack=1, vlan=False):
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 5 << 4, flags, 8192, 0, 0)
    tcp = tcp[:16] + struct.pack("!H", _csum(s + d + struct.pack("!BBH", 0, 6, len(tcp) + len(payload)) + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    eth = bytes([2, 0, 0, 0, 0, 1]) + bytes([2, 0, 0, 0, 0, 2])
    eth += (b"\x81\x00\x00\x64" if vlan else b"") + b"\x08\x00"
    return eth + ip + tcp + payload

def modbus(tid, fc, addr=0, data=b""):
    pdu = bytes([fc]) + struct.pack("!H", addr) + data
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, 1) + pdu

def build_pcap(packets, base=1_760_000_000, big_endian=False, truncate_last=0):
    """packets: list of (offset_seconds, frame_bytes)."""
    e = ">" if big_endian else "<"
    out = struct.pack(e + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, fr in sorted(packets, key=lambda x: x[0]):
        out += struct.pack(e + "IIII", base + int(ts), int((ts % 1) * 1e6), len(fr), len(fr)) + fr
    return out[:-truncate_last] if truncate_last else out
