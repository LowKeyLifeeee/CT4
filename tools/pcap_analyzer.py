"""
pcap_analyzer.py — Công cụ phân tích ICMP Flood từ file Wireshark (.pcap/.pcapng)
Bài lab An toàn mạng — Môi trường VMware (Kali Linux + Windows)

Yêu cầu: pip install scapy pandas matplotlib colorama
"""

import argparse
import json
import csv
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import ICMP, IP, sniff
    from scapy.utils import PcapReader
    from scapy.layers.inet import IP as ScapyIP
except ImportError:
    print("[ERROR] Scapy chưa được cài. Chạy: pip install scapy")
    sys.exit(1)

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = YELLOW = GREEN = CYAN = WHITE = MAGENTA = ""
    class Style:
        RESET_ALL = BRIGHT = ""

# ─────────────────────────── Cấu hình ────────────────────────────
ICMP_TYPES_OF_INTEREST = {
    3: {
        4: "Destination Unreachable – Fragmentation Needed (PMTUD Abuse)",
        0: "Destination Unreachable – Net Unreachable",
        1: "Destination Unreachable – Host Unreachable",
        3: "Destination Unreachable – Port Unreachable",
    },
    4: {0: "Source Quench (Deprecated – RFC 6633)"},
    7: {0: "Unassigned / Reserved (Suspicious)"},
}

DEFAULT_THRESHOLD    = 100   # packets/second
DEFAULT_WINDOW_SEC   = 1     # sliding window (giây)
# ──────────────────────────────────────────────────────────────────


def banner():
    print(f"""{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════╗
║       PCAP ICMP Flood Analyzer  — Lab An Toàn Mạng       ║
║  Phát hiện: ICMP Type 3/4/7  |  Threshold configurable   ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


# ─────────────────── Parse packets từ .pcap ───────────────────────
def load_pcap(path: str) -> list:
    """Đọc file pcap theo luồng (Streaming) để chống cạn kiệt bộ nhớ (OOM/DoS)."""
    print(f"{Fore.CYAN}[*] Đọc file an toàn (Streaming Mode): {path}{Style.RESET_ALL}")
    
    if not Path(path).exists():
        print(f"{Fore.RED}[ERROR] File không tồn tại: {path}{Style.RESET_ALL}")
        sys.exit(1)

    records = []
    try:
        with PcapReader(path) as pcap_reader:
            for pkt in pcap_reader:
                if pkt.haslayer(IP) and pkt.haslayer(ICMP):
                    ip_layer   = pkt[IP]
                    icmp_layer = pkt[ICMP]
                    itype = int(icmp_layer.type)
                    icode = int(icmp_layer.code)
                    if itype in ICMP_TYPES_OF_INTEREST:
                        records.append({
                            "timestamp": float(pkt.time),
                            "src_ip":    ip_layer.src,
                            "dst_ip":    ip_layer.dst,
                            "icmp_type": itype,
                            "icmp_code": icode,
                            "length":    len(pkt),
                        })
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Lỗi Parse PCAP (File hỏng/Mã độc): {e}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Tổng packets ICMP Type 3/4/7 thu thập: {len(records)}{Style.RESET_ALL}")
    return records


# ─────────────────── Phát hiện Flood & DDoS ────────────────────────
def detect_flood(records: list, threshold: int, window: int) -> list:
    """
    Phát hiện DoS (từ 1 IP) và DDoS (từ Mạng Botnet/Spoofed IPs).
    """
    alerts = []
    
    # 1. Phát hiện DoS truyền thống (Single-Source)
    groups_src = defaultdict(list)
    for r in records:
        key = (r["src_ip"], r["icmp_type"], r["icmp_code"])
        groups_src[key].append(r)

    for (src_ip, itype, icode), pkts in groups_src.items():
        pkts.sort(key=lambda x: x["timestamp"])
        timestamps = [p["timestamp"] for p in pkts]
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window:
                left += 1
            count = right - left + 1
            if count >= threshold:
                w_start = timestamps[left]
                w_end   = timestamps[right]
                # Chỉ cảnh báo một lần cho một dải thời gian liên tục
                if not alerts or alerts[-1].get("window_end", 0) < w_start or alerts[-1].get("src_ip") != src_ip:
                    alerts.append({
                        "attack_type":  "Single-Source DoS",
                        "target_ip":    pkts[right]["dst_ip"],
                        "src_ip":       src_ip,
                        "icmp_type":    itype,
                        "icmp_code":    icode,
                        "description":  ICMP_TYPES_OF_INTEREST.get(itype, {}).get(icode, "Unknown"),
                        "pkt_count":    count,
                        "window_start": w_start,
                        "window_end":   w_end,
                        "duration_sec": round(max(w_end - w_start, 0.001), 4),
                        "pps":          round(count / max(w_end - w_start, 0.001), 2),
                        "unique_srcs":  1
                    })

    # 2. Phát hiện DDoS / Phân tán (Multi-Source nhắm vào 1 Mục tiêu)
    groups_dst = defaultdict(list)
    for r in records:
        groups_dst[r["dst_ip"]].append(r)
        
    for dst_ip, pkts in groups_dst.items():
        pkts.sort(key=lambda x: x["timestamp"])
        timestamps = [p["timestamp"] for p in pkts]
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window:
                left += 1
            count = right - left + 1
            if count >= threshold * 1.5:  # DDoS threshold tổng thể cho 1 mục tiêu
                w_start = timestamps[left]
                w_end   = timestamps[right]
                window_pkts = pkts[left:right+1]
                unique_srcs = len(set(p["src_ip"] for p in window_pkts))
                
                # Nếu có nhiều hơn 1 IP nguồn cùng đánh vào 1 IP đích -> DDoS/Botnet
                if unique_srcs > 1:
                    if not alerts or alerts[-1].get("attack_type") != "Distributed DoS (DDoS)" or alerts[-1]["target_ip"] != dst_ip or alerts[-1]["window_start"] != w_start:
                        alerts.append({
                            "attack_type":  "Distributed DoS (DDoS)",
                            "target_ip":    dst_ip,
                            "src_ip":       f"Multiple ({unique_srcs} Spoofed/Botnet IPs)",
                            "icmp_type":    "Mixed",
                            "icmp_code":    "Mixed",
                            "description":  "Nhiều IP phân tán cùng dội bom 1 mục tiêu",
                            "pkt_count":    count,
                            "window_start": w_start,
                            "window_end":   w_end,
                            "duration_sec": round(max(w_end - w_start, 0.001), 4),
                            "pps":          round(count / max(w_end - w_start, 0.001), 2),
                            "unique_srcs":  unique_srcs
                        })

    return alerts


# ─────────────────── Thống kê tổng hợp ───────────────────────────
def summarize(records: list) -> dict:
    """Thống kê theo IP nguồn và loại ICMP."""
    stats = defaultdict(lambda: defaultdict(int))
    for r in records:
        key = f"Type{r['icmp_type']}_Code{r['icmp_code']}"
        stats[r["src_ip"]][key] += 1
    return {ip: dict(counts) for ip, counts in stats.items()}


# ─────────────────── In kết quả ──────────────────────────────────
def print_alerts(alerts: list, threshold: int):
    if not alerts:
        print(f"\n{Fore.GREEN}[✓] Không phát hiện flood vượt ngưỡng {threshold} pkt/s{Style.RESET_ALL}")
        return

    print(f"\n{Fore.RED}{Style.BRIGHT}{'═'*60}")
    print(f"  ⚠  PHÁT HIỆN TẤN CÔNG — {len(alerts)} sự kiện nguy hiểm")
    print(f"{'═'*60}{Style.RESET_ALL}")

    for i, a in enumerate(alerts, 1):
        dt_start = datetime.fromtimestamp(a["window_start"]).strftime("%H:%M:%S.%f")[:-3]
        alert_color = Fore.MAGENTA if "DDoS" in a["attack_type"] else Fore.YELLOW
        print(f"""
{alert_color}[ALERT #{i} - {a['attack_type']}]{Style.RESET_ALL}
  Mục tiêu   : {Fore.RED}{a['target_ip']}{Style.RESET_ALL}
  IP Nguồn   : {a['src_ip']}
  ICMP       : Type {a['icmp_type']} / Code {a['icmp_code']}
  Mô tả      : {a['description']}
  Packets    : {Fore.RED}{a['pkt_count']}{Style.RESET_ALL} pkt trong {a['duration_sec']}s
  Tốc độ     : {Fore.RED}{a['pps']} pkt/s{Style.RESET_ALL}
  Thời điểm  : {dt_start}""")


def print_summary(stats: dict):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'─'*60}")
    print("  THỐNG KÊ THEO IP NGUỒN")
    print(f"{'─'*60}{Style.RESET_ALL}")
    for ip, counts in sorted(stats.items(), key=lambda x: sum(x[1].values()), reverse=True):
        total = sum(counts.values())
        detail = " | ".join(f"{k}:{v}" for k, v in counts.items())
        print(f"  {Fore.WHITE}{ip:<18}{Style.RESET_ALL}  {Fore.YELLOW}{total:>6} pkts{Style.RESET_ALL}  [{detail}]")


# ─────────────────── Export CSV ───────────────────────────────────
def export_csv(alerts: list, records: list, output_path: str):
    path = Path(output_path)
    # Alerts CSV
    alert_file = path.parent / (path.stem + "_alerts.csv")
    with open(alert_file, "w", newline="", encoding="utf-8") as f:
        if alerts:
            writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
            writer.writeheader()
            writer.writerows(alerts)
    print(f"{Fore.GREEN}[+] Alerts CSV → {alert_file}{Style.RESET_ALL}")

    # All records CSV
    record_file = path.parent / (path.stem + "_packets.csv")
    with open(record_file, "w", newline="", encoding="utf-8") as f:
        if records:
            writer = csv.DictWriter(f, fieldnames=records[0].keys())
            writer.writeheader()
            writer.writerows(records)
    print(f"{Fore.GREEN}[+] Packets CSV → {record_file}{Style.RESET_ALL}")


# ─────────────────── Export JSON ──────────────────────────────────
def export_json(alerts: list, stats: dict, output_path: str):
    path = Path(output_path)
    json_file = path.parent / (path.stem + "_report.json")
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_alerts":  len(alerts),
        "alerts":        alerts,
        "ip_summary":    stats,
    }
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"{Fore.GREEN}[+] JSON Report → {json_file}{Style.RESET_ALL}")


# ─────────────────── Biểu đồ Timeline ────────────────────────────
def plot_timeline(records: list, alerts: list, output_path: str):
    if not HAS_MATPLOTLIB:
        print(f"{Fore.YELLOW}[!] matplotlib chưa cài — bỏ qua biểu đồ{Style.RESET_ALL}")
        return
    if not records:
        return

    fig, axes = plt.subplots(2, 1, figsize=(14, 8))
    fig.suptitle("ICMP Flood Analysis — Wireshark PCAP", fontsize=14, fontweight="bold")

    # ── Subplot 1: Packets theo thời gian ──
    ax1 = axes[0]
    if HAS_PANDAS:
        df = pd.DataFrame(records)
        df["dt"] = pd.to_datetime(df["timestamp"], unit="s")
        df.set_index("dt", inplace=True)
        resampled = df.resample("1S").size()
        ax1.fill_between(resampled.index, resampled.values, alpha=0.4, color="royalblue")
        ax1.plot(resampled.index, resampled.values, color="royalblue", linewidth=1.5)
        # Vẽ ngưỡng cảnh báo
        threshold_line = ax1.axhline(y=100, color="red", linestyle="--", linewidth=1.2, label="Threshold (100 pkt/s)")
        ax1.legend()
    ax1.set_title("Số lượng ICMP Packets / Giây")
    ax1.set_ylabel("Packets/s")
    ax1.set_xlabel("Thời gian")
    ax1.grid(True, alpha=0.3)

    # ── Subplot 2: Phân bổ theo IP nguồn ──
    ax2 = axes[1]
    ip_counts = defaultdict(int)
    for r in records:
        ip_counts[r["src_ip"]] += 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ips, counts = zip(*top_ips) if top_ips else ([], [])
    colors = ["#e74c3c" if c >= 100 else "#3498db" for c in counts]
    bars = ax2.barh(ips, counts, color=colors)
    ax2.set_title("Top 10 IP Nguồn (đỏ = vượt ngưỡng)")
    ax2.set_xlabel("Tổng số Packets")
    ax2.grid(True, alpha=0.3, axis="x")

    plt.tight_layout()
    chart_path = Path(output_path).parent / (Path(output_path).stem + "_chart.png")
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"{Fore.GREEN}[+] Biểu đồ PNG → {chart_path}{Style.RESET_ALL}")


# ─────────────────── Real-time Engine (Live NIDS) ──────────────────
class LiveDetector:
    def __init__(self, threshold: int, window: int):
        self.threshold = threshold
        self.window = window
        self.recent_pkts = []
        self.last_alert_time = 0
        self.alert_cooldown = 1.0  # Cooldown 1 giây tránh trôi log console
        self.total_scanned = 0

    def process_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
            return
            
        ip_layer = pkt[IP]
        icmp_layer = pkt[ICMP]
        itype = int(icmp_layer.type)
        icode = int(icmp_layer.code)
        
        # Chỉ quét loại ICMP nguy hiểm
        if itype not in ICMP_TYPES_OF_INTEREST:
            return
            
        self.total_scanned += 1
        now = time.time()
        
        self.recent_pkts.append({
            "timestamp": now,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "icmp_type": itype,
            "icmp_code": icode
        })
        
        # Dọn dẹp RAM (Xóa packet nằm ngoài Sliding Window)
        cutoff = now - self.window
        self.recent_pkts = [p for p in self.recent_pkts if p["timestamp"] >= cutoff]
        
        # Nếu vừa cảnh báo xong, bỏ qua để tránh spam màn hình
        if now - self.last_alert_time < self.alert_cooldown:
            return
            
        # 1. Phát hiện DDoS (Nhiều IP -> 1 Đích)
        dst_counts = defaultdict(list)
        for p in self.recent_pkts:
            dst_counts[p["dst_ip"]].append(p)
            
        for dst_ip, pkts in dst_counts.items():
            if len(pkts) >= self.threshold * 1.5:
                unique_srcs = len(set(p["src_ip"] for p in pkts))
                if unique_srcs > 1:
                    self._alert("Distributed DoS (DDoS)", dst_ip, f"Multiple ({unique_srcs} Botnet IPs)", len(pkts))
                    self.last_alert_time = now
                    return
                    
        # 2. Phát hiện DoS (1 Nguồn -> 1 Đích)
        src_counts = defaultdict(int)
        target_map = {}
        for p in self.recent_pkts:
            src_counts[p["src_ip"]] += 1
            target_map[p["src_ip"]] = p["dst_ip"]
            
        for src_ip, count in src_counts.items():
            if count >= self.threshold:
                self._alert("Single-Source DoS", target_map[src_ip], src_ip, count)
                self.last_alert_time = now
                return

    def _alert(self, attack_type, target, src, count):
        dt = datetime.now().strftime("%H:%M:%S")
        color = Fore.MAGENTA if "DDoS" in attack_type else Fore.YELLOW
        print(f"\n{color}[!] {dt} | CẢNH BÁO {attack_type.upper()} TRỰC TIẾP!{Style.RESET_ALL}")
        print(f"    Mục tiêu: {Fore.RED}{target}{Style.RESET_ALL} | Nguồn: {src} | Tốc độ: {Fore.RED}{count} pkt/{self.window}s{Style.RESET_ALL}\a")

# ─────────────────── Main ────────────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(
        description="Phân tích ICMP Flood (Hỗ trợ Offline PCAP và Real-time Sniffing)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("pcap", nargs="?", help="Đường dẫn file .pcap (Bỏ qua nếu dùng --live)")
    parser.add_argument("--live", action="store_true", help="Kích hoạt chế độ Real-time Sniffing trực tiếp từ Card mạng")
    parser.add_argument("-i", "--interface", help="Card mạng để sniff (VD: eth0, Wi-Fi). Mặc định: Bắt tất cả")
    parser.add_argument("-t", "--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help=f"Ngưỡng packets/giây (mặc định: {DEFAULT_THRESHOLD})")
    parser.add_argument("-w", "--window", type=int, default=DEFAULT_WINDOW_SEC,
                        help=f"Cửa sổ thời gian (giây, mặc định: {DEFAULT_WINDOW_SEC})")
    parser.add_argument("-o", "--output", default="report",
                        help="Tên file output (không cần extension, mặc định: report)")
    parser.add_argument("--csv",   action="store_true", help="Xuất CSV (Chỉ áp dụng Offline)")
    parser.add_argument("--json",  action="store_true", help="Xuất JSON (Chỉ áp dụng Offline)")
    parser.add_argument("--chart", action="store_true", help="Vẽ biểu đồ PNG (Chỉ áp dụng Offline)")
    parser.add_argument("--all",   action="store_true", help="Xuất tất cả định dạng (Chỉ áp dụng Offline)")
    args = parser.parse_args()

    # 1. Chế độ Real-time (LIVE NIDS)
    if args.live:
        print(f"{Fore.CYAN}[*] KHỞI ĐỘNG CHẾ ĐỘ REAL-TIME (LIVE NIDS){Style.RESET_ALL}")
        print(f"    Ngưỡng phát hiện: {args.threshold} pkt / {args.window}s")
        if args.interface:
            print(f"    Lắng nghe trên card: {args.interface}")
        else:
            print(f"    Lắng nghe trên TẤT CẢ card mạng")
        print(f"{Fore.YELLOW}[!] Bấm Ctrl+C để dừng giám sát...{Style.RESET_ALL}\n")
        
        detector = LiveDetector(args.threshold, args.window)
        try:
            # Tham số store=False đảm bảo RAM không bị đầy khi chạy liên tục ngày qua ngày
            sniff(iface=args.interface, filter="icmp", prn=detector.process_packet, store=False)
        except KeyboardInterrupt:
            print(f"\n{Fore.GREEN}[+] Đã dừng hệ thống. Tổng số gói ICMP rủi ro quét qua: {detector.total_scanned}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[ERROR] Lỗi Sniffing (Yêu cầu chạy script bằng quyền Admin/Root): {e}{Style.RESET_ALL}")
        sys.exit(0)

    # 2. Chế độ Offline PCAP
    if not args.pcap:
        parser.print_help()
        sys.exit(1)

    records = load_pcap(args.pcap)
    if not records:
        print(f"{Fore.YELLOW}[!] Không tìm thấy packet ICMP Type 3/4/7 nào{Style.RESET_ALL}")
        sys.exit(0)

    # 2. Phát hiện flood
    print(f"\n{Fore.CYAN}[*] Phân tích với ngưỡng {args.threshold} pkt/{args.window}s...{Style.RESET_ALL}")
    alerts = detect_flood(records, args.threshold, args.window)
    stats  = summarize(records)

    # 3. In kết quả
    print_alerts(alerts, args.threshold)
    print_summary(stats)

    # 4. Export
    output_base = args.output
    if args.csv  or args.all: export_csv(alerts, records, output_base)
    if args.json or args.all: export_json(alerts, stats, output_base)
    if args.chart or args.all: plot_timeline(records, alerts, output_base)

    # 5. Tóm tắt cuối
    print(f"\n{Fore.CYAN}{'═'*60}")
    print(f"  PHÂN TÍCH HOÀN TẤT")
    print(f"  Packets phân tích : {len(records)}")
    print(f"  Cảnh báo FLOOD    : {Fore.RED}{len(alerts)}{Fore.CYAN}")
    print(f"  IPs theo dõi      : {len(stats)}")
    print(f"{'═'*60}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
