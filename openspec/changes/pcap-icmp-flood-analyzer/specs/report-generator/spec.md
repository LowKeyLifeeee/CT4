## Capability: report-generator

### Overview
Xuất kết quả phân tích ra nhiều định dạng.

### Requirements
- **FR-1**: `--csv` → xuất `*_alerts.csv` và `*_packets.csv`
- **FR-2**: `--json` → xuất `*_report.json` với metadata timestamp
- **FR-3**: `--chart` → xuất `*_chart.png` (timeline + top IPs bar chart)
- **FR-4**: `--all` → kích hoạt tất cả 3 định dạng trên
- **FR-5**: Console output có màu sắc (colorama), degradable nếu không có colorama
