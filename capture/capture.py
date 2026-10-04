#!/usr/bin/env python3
"""Per-device traffic feature extraction for the ZT gateway."""

import csv, os, signal, statistics, sys, time
from collections import defaultdict
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, ARP, Ether

IFACE = "wlan0"
GATEWAY_IP = "10.42.0.1"
WINDOW_S = 10
OUT = "/home/staple1244/ztgw/data/features.csv"

DEVICE_CLASS = {
    "f0:16:1d:51:4d:34": "esp32_sensor",
}

FIELDS = [
    "ts", "mac", "device_class",
    "pkt_count", "bytes_total", "bytes_up", "bytes_down", "up_down_ratio",
    "pkt_size_mean", "pkt_size_std", "pkt_size_max",
    "iat_mean", "iat_std",
    "frac_tcp", "frac_udp", "frac_icmp", "frac_arp",
    "syn_count", "rst_count", "fin_count",
    "uniq_dst_ip", "uniq_dst_port", "new_dst_count",
    "hour_of_day",
]


class Window:
    def __init__(self):
        self.times, self.sizes = [], []
        self.bytes_up = self.bytes_down = 0
        self.tcp = self.udp = self.icmp = self.arp = 0
        self.syn = self.rst = self.fin = 0
        self.dst_ips, self.dst_ports = set(), set()


windows = defaultdict(Window)
seen_dsts = defaultdict(set)


def on_packet(pkt):
    if Ether not in pkt:
        return
    src_mac = pkt[Ether].src.lower()
    dst_mac = pkt[Ether].dst.lower()
    if src_mac in DEVICE_CLASS:
        dev_mac, outbound = src_mac, True
    elif dst_mac in DEVICE_CLASS:
        dev_mac, outbound = dst_mac, False
    else:
        return

    w = windows[dev_mac]
    w.times.append(time.time())
    w.sizes.append(len(pkt))

    if ARP in pkt:
        w.arp += 1
        if outbound:
            w.bytes_up += len(pkt)
        else:
            w.bytes_down += len(pkt)
        return
    if IP not in pkt:
        return

    ip = pkt[IP]
    if outbound:
        w.bytes_up += len(pkt)
        w.dst_ips.add(ip.dst)
    else:
        w.bytes_down += len(pkt)

    if TCP in pkt:
        w.tcp += 1
        w.dst_ports.add(int(pkt[TCP].dport))
        f = int(pkt[TCP].flags)
        if f & 0x02:
            w.syn += 1
        if f & 0x04:
            w.rst += 1
        if f & 0x01:
            w.fin += 1
    elif UDP in pkt:
        w.udp += 1
        w.dst_ports.add(int(pkt[UDP].dport))
    elif ICMP in pkt:
        w.icmp += 1


def extract_features(mac, w, now):
    """Shared by training capture and live scoring. Keep it that way."""
    n = len(w.sizes)
    iats = [b - a for a, b in zip(w.times, w.times[1:])] if n > 1 else []
    total = w.bytes_up + w.bytes_down
    proto_n = max(w.tcp + w.udp + w.icmp + w.arp, 1)
    new_dsts = w.dst_ips - seen_dsts[mac]
    seen_dsts[mac] |= w.dst_ips

    return {
        "ts": round(now, 2),
        "mac": mac,
        "device_class": DEVICE_CLASS.get(mac, "unknown"),
        "pkt_count": n,
        "bytes_total": total,
        "bytes_up": w.bytes_up,
        "bytes_down": w.bytes_down,
        "up_down_ratio": round(w.bytes_up / total, 4) if total else 0,
        "pkt_size_mean": round(statistics.fmean(w.sizes), 2) if n else 0,
        "pkt_size_std": round(statistics.pstdev(w.sizes), 2) if n > 1 else 0,
        "pkt_size_max": max(w.sizes) if n else 0,
        "iat_mean": round(statistics.fmean(iats), 4) if iats else 0,
        "iat_std": round(statistics.pstdev(iats), 4) if len(iats) > 1 else 0,
        "frac_tcp": round(w.tcp / proto_n, 4),
        "frac_udp": round(w.udp / proto_n, 4),
        "frac_icmp": round(w.icmp / proto_n, 4),
        "frac_arp": round(w.arp / proto_n, 4),
        "syn_count": w.syn,
        "rst_count": w.rst,
        "fin_count": w.fin,
        "uniq_dst_ip": len(w.dst_ips),
        "uniq_dst_port": len(w.dst_ports),
        "new_dst_count": len(new_dsts),
        "hour_of_day": time.localtime(now).tm_hour,
    }


def main():
    new_file = not os.path.exists(OUT)
    fh = open(OUT, "a", newline="")
    writer = csv.DictWriter(fh, fieldnames=FIELDS)
    if new_file:
        writer.writeheader()
        fh.flush()

    sniffer = AsyncSniffer(iface=IFACE, prn=on_packet, store=False)
    sniffer.start()
    print(f"capturing on {IFACE}, window={WINDOW_S}s -> {OUT}")

    def stop(*_):
        sniffer.stop()
        fh.close()
        print("\nstopped")
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    while True:
        time.sleep(WINDOW_S)
        now = time.time()
        for mac in list(DEVICE_CLASS):
            row = extract_features(mac, windows.pop(mac, Window()), now)
            writer.writerow(row)
            print(f"{row['device_class']:14s} pkts={row['pkt_count']:4d} "
                  f"bytes={row['bytes_total']:6d} "
                  f"sizemean={row['pkt_size_mean']:7.1f} "
                  f"iatstd={row['iat_std']:6.2f} "
                  f"newdst={row['new_dst_count']}")
        fh.flush()


if __name__ == "__main__":
    main()
