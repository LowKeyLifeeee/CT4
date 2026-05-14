## Design

### Architecture

```text
[.pcap file] ──► load_pcap() ──► [records]
                    │              │
                    │              ▼
                    │      detect_flood(threshold, window)
                    │              │
                    │              ├──► Single-Source DoS: group (src, type, code)
                    │              └──► DDoS: group dst, threshold*1.5, unique_src>1
                    ▼
              summarize(records)
                    │
        ┌───────────┼───────────┬──────────────┐
        ▼           ▼           ▼              ▼
 print_alerts  export_csv  export_json   plot_timeline
 print_summary

[--live] ──► sniff(icmp) ──► LiveDetector.process_packet (sliding window thời gian thực)
```

### Thư viện

| Thư viện | Vai trò |
|-----------|---------|
| Scapy | `PcapReader`, layer `IP`/`ICMP`, `sniff`, `wrpcap` |
| pandas | Resample 1s cho biểu đồ (optional) |
| matplotlib | Timeline + bar top 10 IP |
| colorama | Màu console (optional, degrade im lặng) |

### Sliding window (offline)

- Gom bản ghi theo khóa phát hiện (src+type+code cho DoS; dst cho DDoS).
- Sắp xếp theo `timestamp`.
- Hai chỉ số `left`/`right`: duy trì cửa sổ độ dài `window` giây; đếm `right-left+1`.
- Độ phức tạp ~O(n) mỗi nhóm sau khi sort.

### CLI (tham chiếu implementation)

```text
python tools/pcap_analyzer.py <file.pcap> [--live] [-i INTERFACE]
  [-t THRESHOLD] [-w WINDOW] [-o OUTPUT_PREFIX]
  [--csv] [--json] [--chart] [--all]
```

- Offline: bắt buộc có `pcap`; `--all` = bật csv+json+chart.
- Live: `--live`; không cần `pcap`; thường cần quyền admin/root.

### File chính

| File | Mục đích |
|------|----------|
| [tools/pcap_analyzer.py](../../../tools/pcap_analyzer.py) | Toàn bộ pipeline + CLI + live |
| [tools/gen_test_pcap.py](../../../tools/gen_test_pcap.py) | PCAP mẫu `test_capture.pcap` |
| [tools/requirements_lab.txt](../../../tools/requirements_lab.txt) | pip dependencies |

---

## Các bước cho AI (thứ tự gợi ý)

Mỗi bước: đọc code hiện tại → so khớp spec → sửa tối thiểu → chạy lệnh kiểm tra.

### Bước D1 — Khớp `pcap-reader` spec

**Prompt (copy):**

```text
Đọc openspec/changes/pcap-icmp-flood-analyzer/specs/pcap-reader/spec.md và tools/pcap_analyzer.py.
Kiểm tra load_pcap(): PcapReader streaming, lọc IP+ICMP, type 3/4/7 với đúng tập code trong ICMP_TYPES_OF_INTEREST,
trích timestamp/src/dst/type/code/length, thông báo lỗi file không tồn tại hoặc corrupt.
Nếu spec và code lệch (ví dụ live sniff), cập nhật spec HOẶC code theo hướng ít phá vỡ nhất; giải thích trong commit message.
```

### Bước D2 — Khớp `icmp-flood-detector` spec

**Prompt (copy):**

```text
Đọc specs/icmp-flood-detector/spec.md và hàm detect_flood() trong pcap_analyzer.py.
Xác minh: threshold -t, window -w, group key DoS, ngưỡng DDoS 1.5*threshold, unique_src>1,
các trường alert (attack_type, target_ip, src_ip, icmp_type/code, pkt_count, pps, window_start/end, duration_sec, unique_srcs).
Cập nhật spec nếu thiếu mô tả DDoS so với code.
```

### Bước D3 — Khớp `report-generator` spec

**Prompt (copy):**

```text
Đọc specs/report-generator/spec.md và các hàm export_csv, export_json, plot_timeline, print_*.
Xác minh quy tắc tên file {stem}_alerts.csv, {stem}_packets.csv, {stem}_report.json, {stem}_chart.png;
--all bật đủ export offline; matplotlib/pandas thiếu thì in cảnh báo và bỏ qua chart.
```

### Bước D4 — Live mode

**Prompt (copy):**

```text
Rà soát nhánh args.live: sniff store=False, filter icmp, LiveDetector cooldown và sliding window.
Đảm bảo help argparse mô tả đúng; không regression chế độ offline.
```

### Bước D5 — Tài liệu & OpenSpec

**Prompt (copy):**

```text
Đồng bộ openspec/changes/pcap-icmp-flood-analyzer/tasks.md với thực tế repo.
Nếu sửa hành vi công khai, cập nhật tools/LAB_REPORT.md mục cơ chế hoạt động cho khớp.
```
