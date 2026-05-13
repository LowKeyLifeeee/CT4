"""
live_monitor.py — Real-time ICMP Flood Detector via TShark (Wireshark CLI)
Bài lab An toàn mạng — Môi trường VMware (Kali Linux + Windows)

Cách hoạt động:
  Script khởi động TShark (đã cài sẵn với Wireshark) dưới dạng subprocess,
  đọc output theo từng dòng (line-by-line streaming), rồi đưa vào Detection Engine.
  Không cần Scapy sniff(), không bị lỗi Npcap conflict.

Yêu cầu:
  - Wireshark (có TShark) đã cài trên máy Windows
  - Chạy CMD/Terminal bằng quyền Administrator
  - pip install colorama pandas (scapy KHÔNG cần cho live mode)

Sử dụng:
  python live_monitor.py                        # Bắt tất cả card mạng
  python live_monitor.py -i "Wi-Fi"             # Chỉ định card mạng
  python live_monitor.py -i "Ethernet" -t 50   # Ngưỡng 50 pkt/s
  python live_monitor.py --list-interfaces      # Xem danh sách card mạng
"""

import subprocess
import sys
import time
import argparse
import json
import csv
import os
import threading
import http.server
import socketserver
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class Fore:
        RED = YELLOW = GREEN = CYAN = WHITE = MAGENTA = BLUE = ""
    class Style:
        RESET_ALL = BRIGHT = ""

# ─────────────────────────── Cấu hình ────────────────────────────
DEFAULT_THRESHOLD  = 100   # packets/giây để kích hoạt cảnh báo
DEFAULT_WINDOW_SEC = 1     # Sliding window (giây)
ALERT_COOLDOWN_SEC = 1.5   # Chống spam cảnh báo liên tục
LOG_FILE           = "live_alerts.csv"

# Đường dẫn TShark phổ biến trên Windows
TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "tshark",   # Nếu đã add vào PATH
]

ICMP_DANGER_TYPES = {
    3: {
        4: "Destination Unreachable – Fragmentation Needed (PMTUD Abuse)",
        0: "Destination Unreachable – Net Unreachable",
        1: "Destination Unreachable – Host Unreachable",
        3: "Destination Unreachable – Port Unreachable",
    },
    4: {0: "Source Quench (Deprecated – RFC 6633)"},
    7: {0: "Unassigned / Reserved (Suspicious)"},
}
# ──────────────────────────────────────────────────────────────────


def find_tshark() -> str:
    """Tìm đường dẫn TShark trên máy Windows."""
    for path in TSHARK_PATHS:
        try:
            result = subprocess.run(
                [path, "--version"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                return path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def list_interfaces(tshark_path: str):
    """Liệt kê tất cả card mạng mà TShark có thể sniff."""
    print(f"{Fore.CYAN}[*] Danh sách card mạng khả dụng:{Style.RESET_ALL}\n")
    try:
        result = subprocess.run(
            [tshark_path, "-D"],
            capture_output=True, text=True, timeout=5
        )
        print(result.stdout)
        if result.stderr:
            print(f"{Fore.YELLOW}[!] {result.stderr}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")


def banner():
    print(f"""{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════╗
║   Real-time ICMP Flood Detector  — Powered by TShark/Wireshark║
║   NIDS Engine: DoS + DDoS + Ping Flood  |  Sliding Window     ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


# ─────────────────── Detection Engine (Giữ nguyên logic cũ) ───────
class LiveDetector:
    def __init__(self, threshold: int, window: int, log_file: str):
        self.threshold  = threshold
        self.window     = window
        self.recent_pkts = []
        self.last_alert_time   = 0.0
        self.alert_count       = 0
        self.total_scanned     = 0
        self.log_file          = log_file
        self.active_attacks    = {}  # Lưu trữ các luồng tấn công đang diễn ra
        
        # Dashboard data
        self.dashboard_pkts = []
        self.dashboard_alerts = []
        self.lock = threading.Lock()
        
        self._init_log()

    def is_malicious(self, src_ip, dst_ip):
        """Kiểm tra xem gói tin hiện tại có thuộc luồng tấn công đang diễn ra không."""
        now = time.time()
        # Xóa các attack đã hết hạn (sau khi ngừng flood quá thời gian window)
        self.active_attacks = {k: v for k, v in self.active_attacks.items() if v > now}
        
        # Nếu có cuộc tấn công DDoS nhắm vào dst_ip (từ bất kỳ IP nào)
        if (None, dst_ip) in self.active_attacks:
            return True
        # Nếu có cuộc tấn công DoS từ src_ip cụ thể vào dst_ip
        if (src_ip, dst_ip) in self.active_attacks:
            return True
        return False

    def _init_log(self):
        """Tạo file CSV log để lưu cảnh báo."""
        with open(self.log_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "attack_type", "target_ip",
                "src_ip", "pkt_count", "pps", "icmp_type"
            ])

    def feed(self, timestamp: float, src_ip: str, dst_ip: str,
             icmp_type: int, icmp_code: int):
        """Nhận 1 packet từ TShark parser, cập nhật bộ đệm và kiểm tra."""
        self.total_scanned += 1
        now = timestamp if timestamp else time.time()

        # Chỉ đưa vào Sliding Window nếu là gói tin có rủi ro (để tiết kiệm RAM)
        if icmp_type in ICMP_DANGER_TYPES:
            self.recent_pkts.append({
                "timestamp": now,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "icmp_type": icmp_type,
                "icmp_code": icmp_code,
            })

        # Cập nhật dữ liệu cho Web UI
        with self.lock:
            self.dashboard_pkts.append({
                "time": datetime.fromtimestamp(now).strftime('%H:%M:%S.%f')[:-3],
                "src": src_ip,
                "dst": dst_ip,
                "type": icmp_type,
                "code": icmp_code,
                "malicious": self.is_malicious(src_ip, dst_ip)
            })
            if len(self.dashboard_pkts) > 30:
                self.dashboard_pkts.pop(0)

        # Xóa packet cũ nằm ngoài cửa sổ thời gian
        cutoff = now - self.window
        self.recent_pkts = [p for p in self.recent_pkts if p["timestamp"] >= cutoff]

        # Cooldown chống spam
        if now - self.last_alert_time < ALERT_COOLDOWN_SEC:
            return

        # 1. Phát hiện DDoS/Botnet (Nhiều IP → 1 Mục tiêu)
        dst_groups = defaultdict(list)
        for p in self.recent_pkts:
            dst_groups[p["dst_ip"]].append(p)

        for dst_ip, pkts in dst_groups.items():
            if len(pkts) >= self.threshold * 1.5:
                unique_srcs = len(set(p["src_ip"] for p in pkts))
                if unique_srcs > 1:
                    pps = round(len(pkts) / max(self.window, 0.001))
                    self._fire_alert(
                        "Distributed DDoS (Botnet)", dst_ip,
                        f"Multiple ({unique_srcs} IPs)", len(pkts), pps, "Mixed"
                    )
                    self.last_alert_time = now
                    # Đánh dấu đang có DDoS vào IP đích này
                    self.active_attacks[(None, dst_ip)] = now + self.window
                    return

        # 2. Phát hiện DoS đơn lẻ (1 IP Nguồn → 1 Mục tiêu)
        src_groups = defaultdict(list)
        for p in self.recent_pkts:
            src_groups[p["src_ip"]].append(p)

        for src_ip, pkts in src_groups.items():
            if len(pkts) >= self.threshold:
                target   = pkts[-1]["dst_ip"]
                itype    = pkts[-1]["icmp_type"]
                icode    = pkts[-1]["icmp_code"]
                pps      = round(len(pkts) / max(self.window, 0.001))
                desc     = ICMP_DANGER_TYPES.get(itype, {}).get(icode, f"ICMP Type {itype}")
                label    = "Single-Source DoS"
                self._fire_alert(label, target, src_ip, len(pkts), pps, desc)
                self.last_alert_time = now
                # Đánh dấu IP nguồn này đang tấn công IP đích
                self.active_attacks[(src_ip, target)] = now + self.window
                return

    def _fire_alert(self, attack_type, target, src, count, pps, desc):
        """In cảnh báo màu sắc + ghi log CSV."""
        self.alert_count += 1
        dt_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        is_ddos = "DDoS" in attack_type or "Botnet" in attack_type
        color   = Fore.MAGENTA if is_ddos else Fore.YELLOW

        # Cập nhật UI
        with self.lock:
            self.dashboard_alerts.append({
                "time": dt_str,
                "type": attack_type,
                "target": target,
                "src": src,
                "pps": pps
            })
            if len(self.dashboard_alerts) > 10:
                self.dashboard_alerts.pop(0)

        # In ra terminal
        print(f"\n{color}{Style.BRIGHT}{'▓'*60}{Style.RESET_ALL}")
        print(f"{color}[ALERT #{self.alert_count}] {dt_str} — {attack_type.upper()}{Style.RESET_ALL}")
        print(f"  Mục tiêu (Victim) : {Fore.RED}{target}{Style.RESET_ALL}")
        print(f"  IP Nguồn (Attacker): {Fore.RED}{src}{Style.RESET_ALL}")
        print(f"  Tốc độ tấn công   : {Fore.RED}{count} pkt/{self.window}s  ({pps} pkt/s){Style.RESET_ALL}")
        print(f"  Loại tấn công     : {desc}")
        print(f"{color}{'▓'*60}{Style.RESET_ALL}\a")

        # Ghi vào log CSV
        with open(self.log_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(), attack_type,
                target, src, count, pps, desc
            ])

    def print_status(self):
        """In trạng thái giám sát định kỳ (mỗi 5 giây)."""
        now = datetime.now().strftime("%H:%M:%S")
        print(
            f"\r{Fore.CYAN}[{now}] Đang giám sát... "
            f"| Đã quét: {self.total_scanned} pkts "
            f"| Cảnh báo: {Fore.RED if self.alert_count > 0 else Fore.GREEN}"
            f"{self.alert_count}{Fore.CYAN} "
            f"| Buffer: {len(self.recent_pkts)} pkt/window{Style.RESET_ALL}",
            end="", flush=True
        )


# ─────────────────── TShark Parser ────────────────────────────────
def parse_tshark_line(line: str):
    """
    Parse 1 dòng output từ TShark (tab-separated fields).
    Format: frame.time_epoch TAB ip.src TAB ip.dst TAB icmp.type TAB icmp.code
    Trả về tuple (timestamp, src_ip, dst_ip, icmp_type, icmp_code) hoặc None.
    """
    line = line.strip()
    if not line:
        return None
    parts = line.split("\t")
    if len(parts) < 5:
        return None
    try:
        timestamp = float(parts[0]) if parts[0] else time.time()
        src_ip    = parts[1].strip()
        dst_ip    = parts[2].strip()
        icmp_type = int(parts[3].strip()) if parts[3].strip() else -1
        icmp_code = int(parts[4].strip()) if parts[4].strip() else 0

        # Bỏ qua nếu thiếu IP hoặc Type không hợp lệ
        if not src_ip or not dst_ip or icmp_type < 0:
            return None

        return (timestamp, src_ip, dst_ip, icmp_type, icmp_code)
    except (ValueError, IndexError):
        return None


# ─────────────────── Main Loop ─────────────────────────────────────
def run_live(tshark_path: str, interface: str,
             threshold: int, window: int, log_file: str):
    """Khởi động TShark subprocess và đọc output theo thời gian thực."""

    # Lệnh TShark: xuất ra tab-separated fields, không buffer (-l)
    cmd = [
        tshark_path,
        "-l",                        # Line-buffered output (quan trọng!)
        "-n",                        # Không resolve DNS (nhanh hơn)
        "-q",                        # Quiet (không print summary)
        "-T", "fields",              # Output dạng fields
        "-e", "frame.time_epoch",    # Field 1: Unix timestamp
        "-e", "ip.src",              # Field 2: IP nguồn
        "-e", "ip.dst",              # Field 3: IP đích
        "-e", "icmp.type",           # Field 4: ICMP Type
        "-e", "icmp.code",           # Field 5: ICMP Code
        "-f", "icmp",                # BPF filter: chỉ bắt ICMP
    ]
    if interface:
        cmd += ["-i", interface]     # Card mạng cụ thể

    print(f"{Fore.CYAN}[*] Khởi động TShark subprocess...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Lệnh: {' '.join(cmd)}{Style.RESET_ALL}\n")
    print(f"{Fore.GREEN}[✓] Đang lắng nghe... Hãy thử ping từ máy khác!{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Bấm Ctrl+C để dừng.{Style.RESET_ALL}\n")

    global global_detector
    detector = LiveDetector(threshold, window, log_file)
    global_detector = detector
    last_status_time = time.time()

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,               # Line-buffered
            encoding="utf-8",
            errors="replace",
        )

        for line in process.stdout:
            result = parse_tshark_line(line)
            if result:
                timestamp, src_ip, dst_ip, icmp_type, icmp_code = result
                
                # Kiểm tra xem gói tin này có thuộc chuỗi tấn công đã bị phát hiện chưa
                is_malware = detector.is_malicious(src_ip, dst_ip)
                
                dt = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3]
                
                if is_malware:
                    # In nhãn ĐỎ CHÓT cho gói tin rác (Payload DDoS)
                    print(f"{Fore.RED}[{dt}] [DDoS PAYLOAD] {src_ip:<15} → {dst_ip:<15} | ICMP Type {icmp_type:<2} Code {icmp_code}{Style.RESET_ALL}")
                else:
                    # Gói tin bình thường (trước khi vỡ ngưỡng)
                    print(f"{Fore.CYAN}[{dt}]{Style.RESET_ALL} {Fore.WHITE}{src_ip:<15}{Style.RESET_ALL} {Fore.CYAN}→{Style.RESET_ALL} {Fore.WHITE}{dst_ip:<15}{Style.RESET_ALL} | {Fore.BLUE}ICMP Type {icmp_type:<2} Code {icmp_code}{Style.RESET_ALL}")

                # Đưa vào Engine phát hiện
                detector.feed(timestamp, src_ip, dst_ip, icmp_type, icmp_code)

    except KeyboardInterrupt:
        print(f"\n\n{Fore.GREEN}[+] Đã dừng giám sát.{Style.RESET_ALL}")
        if process.poll() is None:
            process.terminate()
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
    finally:
        print(f"\n{Fore.CYAN}{'═'*60}")
        print(f"  TỔNG KẾT PHIÊN GIÁM SÁT")
        print(f"  Packets ICMP quét qua : {detector.total_scanned}")
        print(f"  Cảnh báo phát hiện    : {Fore.RED}{detector.alert_count}{Fore.CYAN}")
        print(f"  Log đã lưu tại        : {log_file}")
        print(f"{'═'*60}{Style.RESET_ALL}\n")


# ─────────────────── Web Server ──────────────────────────────────────
global_detector = None

def start_web_server(port=8080):
    """Khởi động Web Server ngầm để phục vụ Dashboard HTML và API từ RAM."""
    try:
        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                pass # Tắt log HTTP
                
            def do_GET(self):
                # Phục vụ API dashboard.json trực tiếp từ RAM (Chống lag đĩa cứng)
                if self.path.split('?')[0] == '/dashboard.json':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
                    self.end_headers()
                    
                    if global_detector:
                        with global_detector.lock:
                            data = {
                                "total_scanned": global_detector.total_scanned,
                                "alert_count": global_detector.alert_count,
                                "packets": global_detector.dashboard_pkts,
                                "alerts": global_detector.dashboard_alerts
                            }
                        self.wfile.write(json.dumps(data).encode('utf-8'))
                    else:
                        self.wfile.write(b'{}')
                    return
                # Phục vụ file HTML bình thường
                super().do_GET()
                
        # Thay đổi thư mục gốc về đúng nơi chứa dashboard.html
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        
        httpd = socketserver.TCPServer(("", port), QuietHandler)
        print(f"{Fore.GREEN}[*] 🌐 WEB DASHBOARD ĐÃ MỞ TẠI: http://localhost:{port}/dashboard.html{Style.RESET_ALL}\n")
        httpd.serve_forever()
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Không thể khởi động Web UI trên port {port} (Lỗi: {e}).{Style.RESET_ALL}")


# ─────────────────── Entry Point ───────────────────────────────────
def main():
    banner()
    parser = argparse.ArgumentParser(
        description="Real-time ICMP Flood Detector — TShark/Wireshark Backend",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interface",
        help="Card mạng để sniff (VD: 'Wi-Fi', 'Ethernet', '\\Device\\NPF_{UUID}')\nBỏ trống = bắt tất cả card (có thể cần chạy 2 lần để nhận diện)"
    )
    parser.add_argument(
        "-t", "--threshold", type=int, default=DEFAULT_THRESHOLD,
        help=f"Ngưỡng packets/giây để cảnh báo (mặc định: {DEFAULT_THRESHOLD})\nLab test: dùng -t 5 để dễ kích hoạt hơn"
    )
    parser.add_argument(
        "-w", "--window", type=int, default=DEFAULT_WINDOW_SEC,
        help=f"Cửa sổ thời gian tính tốc độ (giây, mặc định: {DEFAULT_WINDOW_SEC})"
    )
    parser.add_argument(
        "-o", "--output", default=LOG_FILE,
        help=f"File CSV lưu cảnh báo (mặc định: {LOG_FILE})"
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="Liệt kê tất cả card mạng khả dụng rồi thoát"
    )
    parser.add_argument(
        "--tshark-path", default=None,
        help="Đường dẫn thủ công đến tshark.exe nếu không tìm thấy tự động"
    )
    args = parser.parse_args()

    # 1. Tìm TShark
    tshark_path = args.tshark_path or find_tshark()
    if not tshark_path:
        print(f"{Fore.RED}[ERROR] Không tìm thấy TShark!{Style.RESET_ALL}")
        print(f"  → Cài Wireshark từ: https://www.wireshark.org/download.html")
        print(f"  → Hoặc chỉ định thủ công: python live_monitor.py --tshark-path 'C:\\...\\tshark.exe'")
        sys.exit(1)

    print(f"{Fore.GREEN}[✓] Tìm thấy TShark: {tshark_path}{Style.RESET_ALL}")

    # 2. Liệt kê card mạng nếu được yêu cầu
    if args.list_interfaces:
        list_interfaces(tshark_path)
        sys.exit(0)

    # 3. In cấu hình đang dùng
    print(f"\n{Fore.CYAN}  Ngưỡng phát hiện : {args.threshold} pkt / {args.window}s")
    print(f"  Card mạng       : {args.interface or 'TẤT CẢ'}")
    print(f"  Log file        : {args.output}{Style.RESET_ALL}\n")

    # 4. Khởi động Web UI Server
    threading.Thread(target=start_web_server, args=(8081,), daemon=True).start()
    time.sleep(1) # Chờ server lên

    # 5. Bắt đầu giám sát (Dừng code ở đây)
    run_live(tshark_path, args.interface, args.threshold, args.window, args.output)


if __name__ == "__main__":
    main()
