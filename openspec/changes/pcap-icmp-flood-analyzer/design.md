## Design

### Architecture

```
[.pcap file] → load_pcap() → [records list]
                                    ↓
                           detect_flood()  ← threshold, window
                                    ↓
                           [alerts list] + summarize()
                                    ↓
                 ┌──────────────────┼──────────────────┐
            print_alerts()    export_csv()        plot_timeline()
                              export_json()
```

### Thư viện
- **Scapy** — Parse pcap, truy cập layer IP/ICMP
- **pandas** — Resample timeline theo giây
- **matplotlib** — Vẽ biểu đồ timeline + bar chart
- **colorama** — Màu sắc console, optional

### Sliding Window Algorithm
Two-pointer O(n) trên timestamps đã sort, tránh O(n²) brute force.

### CLI Interface
```
python pcap_analyzer.py <file.pcap> [-t THRESHOLD] [-w WINDOW] [-o OUTPUT] [--csv] [--json] [--chart] [--all]
```
