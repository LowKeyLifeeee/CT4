## Capability: icmp-flood-detector

### Overview
Sliding-window algorithm phát hiện flooding theo ngưỡng packets/giây từ IP nguồn.

### Requirements
- **FR-1**: Ngưỡng mặc định 100 packets/giây, configurable qua CLI `-t`
- **FR-2**: Cửa sổ sliding window mặc định 1 giây, configurable qua `-w`
- **FR-3**: Track theo `(src_ip, icmp_type, icmp_code)` riêng biệt
- **FR-4**: Output mỗi alert: `src_ip`, `icmp_type`, `icmp_code`, `pkt_count`, `pps`, `window_start`
- **FR-5**: Hỗ trợ phát hiện đồng thời nhiều IP tấn công

### Algorithm
Sliding window O(n) với two-pointer trên mảng timestamp đã sort.
