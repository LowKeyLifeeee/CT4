## Capability: pcap-reader

### Overview
Đọc và parse file `.pcap`/`.pcapng` từ Wireshark bằng thư viện Scapy.

### Requirements
- **FR-1**: Chấp nhận cả định dạng `.pcap` và `.pcapng`
- **FR-2**: Chỉ trích xuất packets có ICMP layer với Type ∈ {3, 4, 7}
- **FR-3**: Trả về: `timestamp`, `src_ip`, `dst_ip`, `icmp_type`, `icmp_code`, `length`
- **FR-4**: Hiển thị thông báo lỗi rõ ràng nếu file không tồn tại hoặc corrupt

### Non-requirements
- Không cần hỗ trợ live capture (chỉ file offline)
