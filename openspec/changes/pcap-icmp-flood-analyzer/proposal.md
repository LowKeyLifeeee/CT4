## Why

Trong bài lab an toàn mạng (VMware: Kali Linux + Windows), sinh viên cần phân tích file `.pcap` từ Wireshark để phát hiện các cuộc tấn công ICMP flood (Type 3/4/7). Việc phân tích thủ công tốn thời gian và dễ bỏ sót; cần một công cụ tự động hóa quy trình này.

## What Changes

- Thêm script Python `pcap_analyzer.py` có khả năng đọc file `.pcap` / `.pcapng`
- Tự động phát hiện ICMP flood dựa trên ngưỡng configurable (mặc định: 100 pkt/s)
- Phân loại theo ICMP Type 3 Code 4, Type 4 (Source Quench), Type 7
- Xuất báo cáo dạng text, CSV và JSON
- Tích hợp visualization timeline bằng matplotlib

## Capabilities

### New Capabilities
- `pcap-reader`: Đọc và parse file `.pcap`/`.pcapng` bằng Scapy
- `icmp-flood-detector`: Phát hiện flood theo ngưỡng packets/second từ IP nguồn
- `report-generator`: Xuất báo cáo CSV, JSON, text summary

### Modified Capabilities
<!-- none -->

## Impact

- Thư viện mới: `scapy`, `pandas`, `matplotlib`
- File mới: `tools/pcap_analyzer.py`, `tools/requirements_lab.txt`
- Không ảnh hưởng dự án AntiSpam hiện tại
