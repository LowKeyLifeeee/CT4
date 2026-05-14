## Capability: pcap-reader

### Overview

Đọc và parse file `.pcap`/`.pcapng` từ Wireshark bằng Scapy; tùy chọn **live sniff** ICMP qua CLI `--live` (xem `pcap_analyzer.py`).

### Requirements

| ID | Yêu cầu | Ghi chú implementation |
|----|----------|-------------------------|
| **FR-1** | Chấp nhận `.pcap` và `.pcapng` | `PcapReader(path)` không phân biệt đuôi nếu libpcap đọc được |
| **FR-2** | Chỉ trích gói có lớp **IP** và **ICMP**; `icmp.type` ∈ {3, 4, 7} và `icmp.code` nằm trong map `ICMP_TYPES_OF_INTEREST` | Bỏ các ICMP khác để giảm nhiễu |
| **FR-3** | Mỗi bản ghi gồm: `timestamp`, `src_ip`, `dst_ip`, `icmp_type`, `icmp_code`, `length` | `timestamp` = `float(pkt.time)` |
| **FR-4** | File không tồn tại: in lỗi rõ, `sys.exit(1)` | Kiểm `Path(path).exists()` |
| **FR-5** | File corrupt / lỗi parse: bắt exception, in `[ERROR]` + message, `sys.exit(1)` | Không để traceback raw cho user lab |
| **FR-6** | (Tùy chọn lab) Đọc PCAP theo **streaming** | `with PcapReader(path) as pcap_reader` — tránh OOM file lớn |

### Non-requirements

- Không bắt buộc tái tạo gói từ đầu (chỉ đọc capture có sẵn), trừ script test riêng `gen_test_pcap.py`.

---

### Việc AI cần làm (checklist)

1. Mở `tools/pcap_analyzer.py`, định vị `load_pcap` và `ICMP_TYPES_OF_INTEREST`.
2. Đối chiếu từng FR với điều kiện `if pkt.haslayer(IP) and pkt.haslayer(ICMP)`.
3. Nếu thêm type/code mới: cập nhật map + bảng trong `LAB_REPORT.md` mục ICMP.

---

### Prompt mẫu (copy cho agent)

```text
Bạn là coding agent. Nhiệm vụ: đảm bảo hàm load_pcap() trong tools/pcap_analyzer.py thỏa mãn toàn bộ FR trong
openspec/changes/pcap-icmp-flood-analyzer/specs/pcap-reader/spec.md.

Hành động:
1) Đọc spec này và load_pcap hiện tại.
2) Liệt kê bảng mapping FR → dòng code (hoặc ghi "thiếu").
3) Nếu thiếu: sửa code tối thiểu; nếu spec lỗi thời (ví dụ đã có live sniff): sửa spec cho khớp code và nêu lý do.
4) Đề xuất một dòng lệnh kiểm thử: python tools/pcap_analyzer.py <file.pcap> (không --live).

Không refactor không liên quan. Không xóa comment hữu ích.
```
