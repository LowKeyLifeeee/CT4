# Báo cáo Lab: Phân tích ICMP Flood với Wireshark và IDS

## 1. Mục tiêu

- Phân tích luồng gói tin ICMP Type 3 Code 4 bằng Wireshark trong môi trường VMware
- Viết rule IDS (Snort/Suricata) để phát hiện flooding
- Tự động hóa phân tích file `.pcap` bằng Python

---

## 2. Môi trường Lab

| Thành phần | Giá trị |
|---|---|
| Hypervisor | VMware Workstation |
| Máy tấn công | Kali Linux — `192.168.56.64` |
| Máy nạn nhân | Windows — `192.168.56.63` |
| Công cụ capture | Wireshark ≥ 4.x |
| Công cụ phân tích | Python 3.10+, Scapy, pandas, matplotlib |

---

## 3. ICMP Types được giám sát

| Type | Code | Tên | Nguy cơ |
|---|---|---|---|
| 3 | 4 | Destination Unreachable – Fragmentation Needed | PMTUD Spoofing / Flood |
| 3 | 0–3 | Destination Unreachable (các variant) | DoS |
| 4 | 0 | Source Quench (deprecated RFC 6633) | Suspicious |
| 7 | 0 | Unassigned / Reserved | Highly suspicious |

---

## 4. Quy trình thực hiện

### Bước 1: Capture traffic trên Wireshark (Kali Linux)

```bash
# Lọc real-time trên Wireshark
icmp.type == 3 && icmp.code == 4

# Hoặc capture toàn bộ ICMP
icmp
```

Lưu file: `File → Export Specified Packets → capture.pcap`

### Bước 2: Phân tích bằng Python

```bash
# Cài dependencies (chỉ 1 lần)
pip install -r tools/requirements_lab.txt

# Sinh PCAP test (nếu chưa có file thật)
python tools/gen_test_pcap.py

# Phân tích và xuất toàn bộ báo cáo
python tools/pcap_analyzer.py test_capture.pcap --all -o output/report
```

### Bước 3: Đọc kết quả

| File output | Nội dung |
|---|---|
| `output/report_alerts.csv` | Danh sách các sự kiện flood |
| `output/report_packets.csv` | Toàn bộ packets ICMP 3/4/7 |
| `output/report_report.json` | JSON đầy đủ với metadata |
| `output/report_chart.png` | Biểu đồ timeline + top IPs |

---

## 5. IDS Rules (Snort/Suricata)

### Snort

```snort
alert icmp any any -> $HOME_NET any (
    msg:"[LAB-IDS] ICMP Type 3 Code 4 Flood - PMTUD Attack";
    itype:3; icode:4;
    detection_filter: track by_src, count 100, seconds 1;
    classtype:attempted-dos; priority:1;
    sid:9000001; rev:1;
)
```

### Suricata

```yaml
alert icmp any any -> $HOME_NET any (
    msg:"[LAB-IDS] ICMP T3C4 Flood from Single Source";
    itype:3; icode:4;
    threshold: type threshold, track by_src, count 100, seconds 1;
    classtype:attempted-dos; priority:1;
    sid:9000002; rev:1;
)
```

---

## 6. Kết quả mong đợi

Khi file `test_capture.pcap` được phân tích:

- **2 ALERT** phát hiện:
  - `192.168.56.101` → ICMP Type 3 Code 4 — ~200 pkt/s (vượt ngưỡng 100)
  - `192.168.56.102` → ICMP Type 4 Code 0 — ~125 pkt/s (vượt ngưỡng 100)
- **Biểu đồ** hiển thị spike rõ ràng tại giây thứ 6 và 10

---

## 7. Công cụ và Files

```
tools/
├── pcap_analyzer.py      ← Script phân tích chính
├── gen_test_pcap.py      ← Sinh PCAP mẫu để test
├── install_lab.bat       ← Cài dependencies (Windows)
└── requirements_lab.txt  ← Danh sách thư viện
```
