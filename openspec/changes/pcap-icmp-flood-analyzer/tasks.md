# Tasks — pcap-icmp-flood-analyzer

## Setup
- [x] Tạo `tools/pcap_analyzer.py`
- [x] Tạo `tools/requirements_lab.txt`

## Implementation (đã hoàn thành)
- [x] `load_pcap()` — đọc file, filter ICMP Type 3/4/7
- [x] `detect_flood()` — sliding window algorithm
- [x] `summarize()` — thống kê theo IP nguồn
- [x] `print_alerts()` + `print_summary()` — console output với màu
- [x] `export_csv()` — xuất alerts và packets ra CSV
- [x] `export_json()` — xuất report JSON
- [x] `plot_timeline()` — biểu đồ timeline + top IPs
- [x] CLI với argparse

## Triển khai trong lab
- [x] Cài dependencies trên máy phân tích: `pip install -r tools/requirements_lab.txt` (`install_lab.bat` tạo sẵn)
- [x] Export `.pcap` từ Wireshark trên Kali Linux (`gen_test_pcap.py` để test offline)
- [x] Chạy: `python tools/pcap_analyzer.py capture.pcap --all`
- [x] Xem báo cáo CSV/JSON/PNG
- [x] Tích hợp kết quả vào báo cáo lab (`LAB_REPORT.md`)
