# Tasks — pcap-icmp-flood-analyzer

Hướng dẫn dưới đây dành cho **AI agent (vibe coding)**: mỗi mục có **Prompt** copy-paste; **Done when** là tiêu chí nghiệm thu tối thiểu.

---

## Setup (scaffold)

- [x] Tạo `tools/pcap_analyzer.py`
- [x] Tạo `tools/requirements_lab.txt`

**Prompt (nếu tạo mới từ đầu trong repo trống):**

```text
Tạo tools/requirements_lab.txt với scapy, pandas, matplotlib, colorama (phiên bản tương thích Python 3.10+).
Tạo tools/pcap_analyzer.py skeleton: argparse với pcap optional khi --live, -t -w -o, flags --csv --json --chart --all,
import scapy an toàn với thông báo nếu thiếu. Chưa cần logic flood đầy đủ — chỉ load 1 gói ICMP test được.
```

**Done when:** `pip install -r tools/requirements_lab.txt` thành công; chạy script `--help` không lỗi.

---

## T1 — `load_pcap()` (capability `pcap-reader`)

- [x] Đọc file `.pcap`/`.pcapng` bằng `PcapReader` (streaming)
- [x] Lọc gói có `IP` + `ICMP`, type ∈ {3,4,7} và code trong `ICMP_TYPES_OF_INTEREST`
- [x] Trả về list dict: timestamp, src_ip, dst_ip, icmp_type, icmp_code, length
- [x] Thoát có mã lỗi + message nếu file không tồn tại hoặc corrupt

**Prompt:**

```text
Trong tools/pcap_analyzer.py, triển khai load_pcap(path) theo openspec/changes/pcap-icmp-flood-analyzer/specs/pcap-reader/spec.md.
Dùng PcapReader(path) as reader, vòng for từng pkt; chỉ append khi haslayer(IP) and haslayer(ICMP) và (type,code) thuộc ICMP_TYPES_OF_INTEREST.
Bắt Exception khi parse, in [ERROR] và sys.exit(1). In số bản ghi thu được.
```

**Done when:** Chạy trên `test_capture.pcap` (sau T6) trả về >0 records hoặc thoát rõ ràng nếu file không có ICMP hợp lệ.

---

## T2 — `detect_flood()` (capability `icmp-flood-detector`)

- [x] Sliding window O(n) theo nhóm `(src_ip, icmp_type, icmp_code)` cho Single-Source DoS
- [x] Sliding window theo `dst_ip` với ngưỡng 1.5×threshold và `unique_srcs > 1` cho DDoS
- [x] Tham số `threshold`, `window` từ CLI

**Prompt:**

```text
Triển khai detect_flood(records, threshold, window) trong pcap_analyzer.py theo specs/icmp-flood-detector/spec.md và design.md.
DoS: defaultdict list theo (src_ip, itype, icode), sort timestamp, two-pointer.
DDoS: defaultdict theo dst_ip, cùng two-pointer, count >= int(threshold*1.5) hoặc threshold*1.5 float, unique_srcs=len(set(...))>1.
Trả về list alert dict đủ field để export_csv/json và print_alerts.
```

**Done when:** PCAP mẫu có ít nhất một alert DoS; DDoS segment tạo alert DDoS khi đủ điều kiện.

---

## T3 — `summarize()` + console

- [x] `summarize(records)` theo IP nguồn và Type_Code
- [x] `print_alerts`, `print_summary` với colorama nếu có

**Prompt:**

```text
Thêm summarize(), print_alerts(), print_summary() vào pcap_analyzer.py.
summarize: defaultdict nested đếm key Type{type}_Code{code} per src_ip.
print_*: dùng Fore/Style nếu HAS_COLOR else chuỗi rỗng; định dạng dễ đọc.
```

**Done when:** Chạy offline in ra bảng thống kê và danh sách alert không traceback.

---

## T4 — Export CSV / JSON (capability `report-generator`)

- [x] `export_csv` → `{stem}_alerts.csv`, `{stem}_packets.csv`
- [x] `export_json` → `{stem}_report.json` (generated_at, total_alerts, alerts, ip_summary)

**Prompt:**

```text
Triển khai export_csv và export_json trong pcap_analyzer.py.
CSV: DictWriter utf-8, fieldnames từ keys phần tử đầu list.
JSON: dict report với datetime.now().isoformat(), indent=2, ensure_ascii=False.
Đường dẫn: Path(output).parent / (stem + suffix); stem = Path(output).stem.
```

**Done when:** `python tools/pcap_analyzer.py test_capture.pcap --csv --json -o out/x` tạo đủ 3 file trong thư mục `out/`.

---

## T5 — `plot_timeline()` + `--all`

- [x] PNG timeline (resample 1s nếu có pandas) + top 10 IP bar
- [x] `--all` bật csv+json+chart

**Prompt:**

```text
plot_timeline(records, alerts, output_path): nếu không có matplotlib thì warning và return.
Hai subplot: (1) packets/s theo thời gian, axhline threshold 100, legend; (2) barh top 10 src_ip.
Lưu {stem}_chart.png dpi=150. Wire main() để --all gọi export_csv, export_json, plot_timeline.
```

**Done when:** `--all` tạo thêm PNG; không pandas vẫn không crash (fallback nếu code có).

---

## T6 — CLI hoàn chỉnh + `gen_test_pcap.py`

- [x] argparse: positional pcap, -t -w -o, --csv --json --chart --all
- [x] `tools/gen_test_pcap.py` sinh `test_capture.pcap` với các phase flood/DDoS

**Prompt:**

```text
Hoàn thiện main() trong pcap_analyzer.py: không pcap và không --live thì print_help exit 1.
gen_test_pcap.py: dùng scapy wrpcap, các đoạn background, flood T3C4 từ ATTACKER_IP, T4 burst, DDoS nhiều src, recovery; sort theo pkt.time.
```

**Done when:** `python tools/gen_test_pcap.py` (cwd `tools`) tạo test_capture.pcap; analyzer chạy `--all` không lỗi.

---

## T7 — Chế độ `--live` (NIDS nhẹ)

- [x] `--live`, `-i/--interface`, `sniff(..., store=False)`, class `LiveDetector`

**Prompt:**

```text
Thêm nhánh args.live trong pcap_analyzer.py: class LiveDetector với threshold, window, recent_pkts list,
dọn gói theo cutoff now-window, cooldown last_alert_time, kiểm tra DDoS trước rồi DoS như code mẫu chuẩn IDS nhẹ.
sniff(iface=args.interface or None, filter="icmp", prn=detector.process_packet, store=False).
KeyboardInterrupt in thông báo tổng gói quét.
```

**Done when:** `--help` liệt kê --live và -i; chạy --live trên máy có quyền không crash ngay (có thể Ctrl+C).

---

## T8 — Triển khai lab & tài liệu

- [x] `install_lab.bat` (Windows) hoặc hướng dẫn pip
- [x] `tools/LAB_REPORT.md` mô tả quy trình và cơ chế tool
- [x] OpenSpec proposal/design/specs/tasks đồng bộ ý nghĩa

**Prompt:**

```text
Đọc tools/LAB_REPORT.md và openspec/changes/pcap-icmp-flood-analyzer/*.md.
Đảm bảo lệnh mẫu trong LAB_REPORT khớp đường dẫn (tools/, output/). Cập nhật tasks checklist [x] phản ánh trạng thái thật.
```

**Done when:** Người mới clone repo làm theo LAB_REPORT + tasks mà không mơ hồ bước tiếp theo.

---

## Lệnh kiểm tra nhanh (human hoặc agent)

```bash
cd tools
pip install -r requirements_lab.txt
python gen_test_pcap.py
python pcap_analyzer.py test_capture.pcap --all -o output/report
```

Kỳ vọng: thư mục `output/` có `report_alerts.csv`, `report_packets.csv`, `report_report.json`, `report_chart.png` (prefix phụ thuộc `-o`).
