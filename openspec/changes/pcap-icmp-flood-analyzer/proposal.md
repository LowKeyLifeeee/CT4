## Why

Trong bài lab an toàn mạng (VMware: Kali Linux + Windows), sinh viên cần phân tích file `.pcap` từ Wireshark để phát hiện các cuộc tấn công ICMP flood (Type 3/4/7). Việc phân tích thủ công tốn thời gian và dễ bỏ sót; cần một công cụ tự động hóa quy trình này.

## What Changes

- Script Python `tools/pcap_analyzer.py`: đọc `.pcap` / `.pcapng`, lọc ICMP Type 3/4/7 (theo bảng code quan tâm trong code).
- Phát hiện flood: ngưỡng và cửa sổ thời gian cấu hình được; DoS một nguồn và DDoS nhiều nguồn → một đích (theo implementation hiện tại).
- Xuất: console có màu (nếu có colorama), CSV, JSON, PNG (matplotlib/pandas nếu có).
- Tùy chọn giám sát trực tiếp: `--live` với Scapy `sniff`.
- Script mẫu: `tools/gen_test_pcap.py`; dependencies: `tools/requirements_lab.txt`.

## Capabilities

### New Capabilities

| Capability | Delta spec | Trách nhiệm ngắn |
|------------|------------|-----------------|
| `pcap-reader` | [specs/pcap-reader/spec.md](specs/pcap-reader/spec.md) | Đọc PCAP, lọc ICMP, trích trường; lỗi file rõ ràng; live sniff tùy chọn |
| `icmp-flood-detector` | [specs/icmp-flood-detector/spec.md](specs/icmp-flood-detector/spec.md) | Sliding window, DoS/DDoS, thống kê |
| `report-generator` | [specs/report-generator/spec.md](specs/report-generator/spec.md) | CSV/JSON/PNG, `--all`, in console |

### Modified Capabilities

- Không có capability chính thức khác trong repo bị sửa ngoài thư mục `tools/` và tài liệu lab.

## Impact

- Thư viện: `scapy`, tùy `pandas`, `matplotlib`, `colorama`.
- File: chủ yếu `tools/*`, `tools/LAB_REPORT.md`.
- Không đụng lõi dự án khác nếu không nằm trong phạm vi change.

## Non-goals (phạm vi ngoài)

- Không yêu cầu engine Snort/Suricata chạy trong repo (chỉ rule mẫu trong báo cáo).
- Không bắt buộc GUI; CLI là đủ.
- Không thay thế Wireshark — chỉ hậu xử lý file capture hoặc sniff bổ trợ.

---

## Prompt tổng (vibe coding — dán cho AI agent)

Dùng khối sau làm system hoặc đầu message khi muốn agent triển khai/review toàn bộ change này:

```text
Bạn đang làm việc trong repo CT4. Change OpenSpec: pcap-icmp-flood-analyzer.

Mục tiêu: đảm bảo tools/pcap_analyzer.py và gen_test_pcap.py khớp delta specs trong
openspec/changes/pcap-icmp-flood-analyzer/specs/*/spec.md và tasks.md.

Ràng buộc:
- Đọc design.md và từng spec trước khi sửa code.
- Giữ CLI argparse tương thích ngược (pcap positional, -t, -w, -o, --csv, --json, --chart, --all, --live, -i).
- Streaming đọc PCAP (PcapReader), không đọc toàn file raw vào RAM không cần thiết.
- Sau thay đổi: chạy python tools/gen_test_pcap.py (từ thư mục tools hoặc chỉnh đường dẫn output) và
  python tools/pcap_analyzer.py test_capture.pcap --all -o output/report nếu có thể.

Đầu ra: diff tối thiểu; cập nhật tasks.md checkbox nếu hoàn thành việc mới.
```
