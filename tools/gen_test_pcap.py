"""
gen_test_pcap.py — Sinh file .pcap mẫu để test pcap_analyzer.py
Mô phỏng tấn công ICMP Type 3 Code 4 Flood từ Kali Linux

Yêu cầu: pip install scapy
Chạy: python gen_test_pcap.py
"""

import sys
import random
import time

try:
    from scapy.all import wrpcap, IP, ICMP, Ether
except ImportError:
    print("[ERROR] Scapy chưa cài. Chạy: pip install scapy")
    sys.exit(1)

ATTACKER_IP   = "192.168.56.64"   # Kali Linux (attacker)
VICTIM_IP     = "192.168.56.63"     # Windows (victim)
NORMAL_IPS    = ["10.0.0.2", "10.0.0.3", "10.0.0.4"]  # traffic bình thường
OUTPUT_FILE   = "test_capture.pcap"

packets = []
base_time = time.time()

print("[*] Đang sinh PCAP mẫu...")

# ── 1. Background traffic bình thường (ICMP Type 3 Code 1 — Host Unreachable) ──
print("    [+] Sinh background traffic (10 pkt/s, 5 giây)...")
for i in range(50):
    src = random.choice(NORMAL_IPS)
    pkt = (
        IP(src=src, dst=VICTIM_IP) /
        ICMP(type=3, code=1)
    )
    pkt.time = base_time + (i * 0.1)  # 10 pkt/s
    packets.append(pkt)

# ── 2. ICMP Flood tấn công — Type 3 Code 4 (vượt ngưỡng 100 pkt/s) ──
print("    [+] Sinh FLOOD attack (200 pkt/s, 3 giây) từ Kali...")
flood_start = base_time + 6.0
for i in range(600):
    pkt = (
        IP(src=ATTACKER_IP, dst=VICTIM_IP) /
        ICMP(type=3, code=4)
    )
    pkt.time = flood_start + (i * 0.005)   # 200 pkt/s
    packets.append(pkt)

# ── 3. ICMP Type 4 Source Quench (deprecated, suspicious) ──
print("    [+] Sinh ICMP Type 4 Source Quench...")
type4_start = base_time + 10.0
for i in range(120):
    pkt = (
        IP(src="192.168.56.102", dst=VICTIM_IP) /
        ICMP(type=4, code=0)
    )
    pkt.time = type4_start + (i * 0.008)   # 125 pkt/s
    packets.append(pkt)

# ── 4. Tấn công DDoS Phân tán / Botnet (Nhiều IP cùng đánh) ──
print("    [+] Sinh DDoS / Botnet attack (300 pkt/s, 4 giây, từ 50 IP khác nhau)...")
ddos_start = base_time + 13.0
for i in range(1200):
    bot_ip = f"113.190.{random.randint(1, 254)}.{random.randint(1, 254)}"
    pkt = (
        IP(src=bot_ip, dst=VICTIM_IP) /
        ICMP(type=3, code=4)
    )
    pkt.time = ddos_start + (i * 0.0033)   # 300 pkt/s phân tán
    packets.append(pkt)

# ── 5. Traffic trở lại bình thường sau flood ──
print("    [+] Sinh post-attack traffic...")
recovery_start = base_time + 18.0
for i in range(30):
    src = random.choice(NORMAL_IPS)
    pkt = (
        IP(src=src, dst=VICTIM_IP) /
        ICMP(type=3, code=3)
    )
    pkt.time = recovery_start + (i * 0.2)
    packets.append(pkt)

# ── Sắp xếp theo thời gian và ghi file ──
packets.sort(key=lambda p: p.time)
wrpcap(OUTPUT_FILE, packets)

print(f"\n[OK] File PCAP mẫu đã tạo: {OUTPUT_FILE}")
print(f"     Tổng packets: {len(packets)}")
print(f"\nTest ngay:")
print(f"  python pcap_analyzer.py {OUTPUT_FILE} --all")
print(f"  python pcap_analyzer.py {OUTPUT_FILE} -t 100 --chart")
