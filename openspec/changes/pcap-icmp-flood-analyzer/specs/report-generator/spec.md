## Capability: report-generator

### Overview

Xuất kết quả phân tích offline: **CSV** (alerts + toàn bộ packets đã lọc), **JSON** (metadata + alerts + ip_summary), **PNG** (timeline + top IP). Console có **màu** nếu cài colorama.

### Requirements

| ID | Yêu cầu | Chi tiết để AI implement/review |
|----|----------|-----------------------------------|
| **FR-1** | `--csv` | Tạo `{stem}_alerts.csv` và `{stem}_packets.csv` cùng thư mục với prefix `-o` |
| **FR-2** | `--json` | `{stem}_report.json`: `generated_at` (ISO), `total_alerts`, `alerts`, `ip_summary` |
| **FR-3** | `--chart` | `{stem}_chart.png`: 2 subplot — ICMP/giây (resample 1s nếu có pandas) + top 10 `src_ip` |
| **FR-4** | `--all` | Tương đương bật `--csv` + `--json` + `--chart` (chỉ **offline**) |
| **FR-5** | Console màu | Dùng colorama nếu import được; nếu không: class Fore/Style rỗng (degrade) |
| **FR-6** | Thiếu matplotlib | In cảnh báo, **không** crash toàn script; bỏ qua vẽ chart |
| **FR-7** | Thiếu pandas | Vẫn vẽ chart được nếu code có nhánh fallback (hoặc chỉ resample khi HAS_PANDAS) |

### Quy ước tên file

- `output_path` truyền vào export/plot là **prefix không extension** (ví dụ `-o output/report` → stem `report`, parent `output/`).

### Non-requirements

- Không yêu cầu xuất PDF/HTML.
- Live mode (`--live`) **không** bắt buộc ghi CSV/JSON/PNG trong spec này (chỉ console).

---

### Việc AI cần làm (checklist)

1. Kiểm `main()`: chỉ gọi export/plot khi **không** `--live` và có `records`.
2. Đảm bảo `Path(output).parent.mkdir(parents=True, exist_ok=True)` nếu thư mục chưa tồn tại — **nếu code hiện tại chưa tạo thư mục**, thêm và cập nhật FR (hoặc ghi vào tasks là bước bổ sung).
3. Kiểm tra encoding UTF-8 cho CSV/JSON tiếng Việt trong alert.

---

### Prompt mẫu (copy cho agent)

```text
Rà soát report-generator trong tools/pcap_analyzer.py theo
openspec/changes/pcap-icmp-flood-analyzer/specs/report-generator/spec.md.

Việc cần làm:
1) Xác minh export_csv, export_json, plot_timeline tạo đúng tên {stem}_*.csv/json/png.
2) Xác minh --all kích hoạt cả ba khi offline.
3) plot_timeline: nếu không có matplotlib thì return sớm; nếu không có pandas thì không được traceback (nhánh thay thế hoặc bỏ resample).
4) Nếu thư mục output chưa tồn tại: tạo mkdir -p tương đương bằng Path(...).mkdir(parents=True, exist_ok=True) trước khi ghi file.

Chỉ sửa pcap_analyzer.py (và spec nếu cần phản ánh hành vi mkdir). Chạy: python tools/pcap_analyzer.py test_capture.pcap --all -o output/report
```
