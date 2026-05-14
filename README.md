# 🛡️ Real-time ICMP Flood Detector (DDoS Monitor)

Đây là một công cụ phát hiện tấn công DDoS (chủ yếu là ICMP Flood / Ping Flood) theo thời gian thực dành cho hệ điều hành Windows. Công cụ sử dụng `TShark` (chương trình dòng lệnh đi kèm Wireshark) để bắt và phân tích luồng mạng ở tốc độ cao.
Báo cáo được viết trong tools/LAB_REPORT.md
## ✨ Tính năng chính
- **Quét Real-time:** Đọc luồng mạng và phân tích gói tin trực tiếp mà không bị gián đoạn.
- **Tự động bắt quyền:** Tự động gọi màn hình cấp quyền Quản trị viên (Administrator).
- **Interactive UI (Terminal):** Cho phép chọn thủ công đường dẫn `tshark.exe` và chọn Card mạng từ danh sách.
- **Web Dashboard:** Hỗ trợ xem trực quan trên trình duyệt (Charts, Logs) qua cổng nội bộ.
- **Log Cảnh báo:** Tự động ghi lại các cảnh báo tấn công DDoS vào tệp `live_alerts.csv`.

## 📂 Các thành phần (Files)
Để công cụ hoạt động, bạn chỉ cần giữ lại 2 file này trong cùng một thư mục:
- `live_monitor.exe`: Công cụ chính đã được đóng gói (không yêu cầu cài đặt Python).
- `dashboard.html`: Tệp giao diện Web. Cung cấp một bảng điều khiển trực quan với đồ thị và danh sách gói tin khi truy cập http://localhost:8081/dashboard.html.

## 🚀 Hướng dẫn cài đặt (Dành cho người nhận)

### Yêu cầu duy nhất:
Công cụ sử dụng engine phân tích mạng của Wireshark. Do đó, máy tính của bạn **BẮT BUỘC** phải cài đặt Wireshark.
👉 **Tải và cài đặt Wireshark tại đây:** [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)

### Cách sử dụng:
1. Giải nén thư mục chứa `live_monitor.exe` và `dashboard.html`.
2. Click đúp chuột vào tệp `live_monitor.exe` để khởi chạy.
3. Chấp nhận bảng hỏi quyền Administrator (màn hình YES/NO của Windows) để cấp quyền cho phép quét mạng.
4. Làm theo hướng dẫn trên màn hình CMD:
   - Nếu máy tính chưa nhận diện được Wireshark, nó sẽ yêu cầu bạn nhập đường dẫn tay (ví dụ: `C:\Program Files\Wireshark\tshark.exe`).
   - Màn hình sẽ hiển thị các Card mạng hiện có (Ethernet, Wi-Fi,...). Hãy gõ **số thứ tự** của Card mạng đang kết nối internet và nhấn Enter.
5. Công cụ bắt đầu chạy. Bạn có thể mở trình duyệt và truy cập `http://localhost:8081/dashboard.html` để xem giao diện đồ hoạ trực quan.
6. Khi muốn thoát ứng dụng, hãy nhấn `Ctrl + C` trên bàn phím.

---
*Lưu ý: Vì đây là phần mềm đóng gói bằng PyInstaller có tác vụ quét mạng, một số trình duyệt hoặc chương trình Diệt Virus (như Windows Defender) có thể nhận diện nhầm là phần mềm độc hại. Vui lòng cho phép tệp này chạy nếu có cảnh báo.*
