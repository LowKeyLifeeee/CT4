## Capability: icmp-flood-detector

### Overview

Phát hiện **ICMP flood** bằng **cửa sổ trượt** (sliding window) trên chuỗi thời gian đã sắp xếp: (1) DoS một nguồn theo `(src_ip, icmp_type, icmp_code)`; (2) DDoS nhiều nguồn nhắm một `dst_ip`.

### Requirements

| ID | Yêu cầu | Chi tiết kỹ thuật (để AI implement/review) |
|----|----------|-----------------------------------------------|
| **FR-1** | Ngưỡng mặc định **100** gói trong cửa sổ | CLI `-t` / `--threshold` |
| **FR-2** | Cửa sổ mặc định **1** giây | CLI `-w` / `--window` — đơn vị giây (float timestamp) |
| **FR-3** | DoS: track riêng theo `(src_ip, icmp_type, icmp_code)` | `defaultdict(list)` + sort theo `timestamp` + two-pointer |
| **FR-4** | Mỗi alert DoS gồm ít nhất: `src_ip`, `dst_ip` (mục tiêu), `icmp_type`, `icmp_code`, `pkt_count`, `pps`, `window_start`, `window_end`, mô tả | Field `attack_type`: `Single-Source DoS` |
| **FR-5** | Nhiều IP tấn công độc lập | Mỗi nhóm `(src, type, code)` xử lý riêng → nhiều alert có thể xuất hiện |
| **FR-6** | DDoS: gom theo `dst_ip` | Trong cửa sổ: `count >= threshold * 1.5` và `unique_srcs > 1` |
| **FR-7** | Alert DDoS: `attack_type` = `Distributed DoS (DDoS)`, `icmp_type/code` có thể `Mixed` | `src_ip` chuỗi dạng `Multiple (N ...)` |
| **FR-8** | Thống kê `summarize(records)` | Đếm theo `src_ip` và nhãn `Type{t}_Code{c}` |

### Algorithm (chuẩn bài lab)

- Với mỗi nhóm bản ghi đã sort theo `timestamp[i]`:
  - `left = 0`
  - Với mỗi `right`, while `ts[right] - ts[left] > window`: `left += 1`
  - `count = right - left + 1`; so sánh ngưỡng tương ứng (DoS: `threshold`; DDoS: `1.5 * threshold`)

### Non-requirements

- Không yêu cầu machine learning hay signature Snort tích hợp trong Python.

---

### Việc AI cần làm (checklist)

1. Đọc `detect_flood()` và đối chiếu bảng FR.
2. Kiểm tra edge case: ít hơn `threshold` gói → không alert; cửa sổ rỗng.
3. Nếu đổi ngưỡng DDoS: cập nhật spec + `design.md` + prompt trong `tasks.md` (T2).

---

### Prompt mẫu (copy cho agent)

```text
Review và/hoặc sửa detect_flood() + summarize() trong tools/pcap_analyzer.py theo
openspec/changes/pcap-icmp-flood-analyzer/specs/icmp-flood-detector/spec.md.

Yêu cầu:
- Giữ độ phức tạp tuyến tính trên mỗi nhóm sau sort (two-pointer), không nested loop O(n^2) trên toàn tập.
- Đảm bảo DDoS chỉ kích hoạt khi unique_srcs > 1 và count đạt 1.5*threshold trong cùng window giây.
- In/alert phải có pps hợp lý (count / duration), tránh chia cho 0 (dùng max(..., 0.001)).

Sau sửa: chạy trên test_capture.pcap từ gen_test_pcap và báo cáo số alert DoS/DDoS nhận được.
```
