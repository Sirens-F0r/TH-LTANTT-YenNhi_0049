# YenNhi_0049
# 🛡️ Secure Validator Lab 01
---

## 🐞 Chi tiết Lỗ hổng (Vulnerability Analysis)

### 1. Xác thực Email: Homograph Attack (Lỗi Regex)
* **Nguyên nhân:** Trong Python 3, ký tự `\w` mặc định khớp với toàn bộ ký tự Unicode (bao gồm chữ Ả Rập, chữ Hán, v.v.) chứ không chỉ giới hạn trong `[a-zA-Z0-9_]`.
* **Khai thác (Bypass):** Hệ thống backend có thể bị lừa bởi các ký tự giả mạo giống hệt nhau về mặt thị giác nhưng khác mã Unicode.
* **Payload test:** `ádmín@example.com`

### 2. Lọc SQL: SQL Injection (Lỗi Blacklist lỏng lẻo)
* **Nguyên nhân:** Cơ chế làm sạch (Sanitization) chỉ xóa một số từ khóa (`OR`, `AND`) và ký tự (`--`, `;`, `'`, `"`, `#`) cố định. Hàm hoàn toàn không chặn các toán tử logic tương đương trên hệ quản trị CSDL như `||` và `&&`.
* **Khai thác (Bypass):** Kẻ tấn công thay đổi cú pháp để vượt qua danh sách đen.
* **Payload test:** `' || 1=1 /*`

### 3. Xác thực URL: Server-Side Request Forgery (SSRF)
* **Nguyên nhân:** Hàm kiểm tra chỉ dùng `urlparse` để soi xem đường link có ghi địa chỉ (domain/IP) và scheme (`http`/`https`) hay không. Nó không hề kiểm tra xem địa chỉ đó là hướng ra ngoài Internet (Public IP) hay chỉ ngược vào mạng nội bộ (Private IP).
* **Hướng khắc phục:** Cần bổ sung logic nhận diện và chặn các dải IP nội bộ như `127.0.0.1`, `192.168.x.x`, hay `10.x.x.x` (bao gồm cả các biến thể quy đổi sang hệ thập phân).
* **Payload test:** `http://2130706433/` *(Dạng thập phân của 127.0.0.1)*

### 4. Xác thực Tên File: Path Traversal & Null Byte Injection
* **Nguyên nhân:** Blacklist chỉ chặn các chuỗi lùi thư mục cơ bản như `..`, `/`, `\`. Tuy nhiên, trong ngôn ngữ C (nền tảng của HĐH), ký tự Null Byte (`\x00` hoặc `%00`) là dấu hiệu kết thúc chuỗi. Bất cứ chữ gì nằm sau ký tự này đều bị HĐH tự động ngắt bỏ.
* **Khai thác (Bypass):** Truyền payload có đuôi hợp lệ nhưng chứa Null Byte ở giữa. Lớp Python cho qua nhưng HĐH lại cắt bỏ phần đuôi an toàn.
* **Payload test:** `passwd.txt%00.jpg`

### 5. Lọc HTML: Cross-Site Scripting (XSS)
* **Nguyên nhân:** Lỗi *Unquoted Attributes*. Code HTML không bọc các giá trị biến vào trong dấu ngoặc kép `" "` để biến chúng thành văn bản tĩnh thuần túy. 
* **Khai thác (Bypass):** Vì không có ngoặc kép, trình duyệt sẽ dùng khoảng trắng để tách câu lệnh. Khi kẻ tấn công chèn một khoảng trắng, cụm mã độc phía sau sẽ bị trình duyệt hiểu nhầm là một thuộc tính thực thi mới.
* **Payload test:** ` x onmouseover=alert(1)`

---

## 🚀 Hướng dẫn Kiểm thử (Proof of Concept)

Bộ Unit Test được cung cấp trong thư mục `tests/` đóng vai trò như một máy quét lỗ hổng. Chạy lệnh sau trong Terminal để xác nhận các payload mã độc đã bypass thành công hệ thống phòng ngự (hệ thống sẽ báo `F` - Fail cho từng lỗ hổng bị xuyên thủng).
<img width="707" height="466" alt="Screenshot 2026-09-23 154701" src="https://github.com/user-attachments/assets/fa219f08-c777-4657-8241-68cbad2e348e" />
<img width="695" height="349" alt="Screenshot 2026-09-23 154716" src="https://github.com/user-attachments/assets/850370d7-1fa5-46e0-80fc-1f6757afada0" />

```bash
python -m unittest discover tests
```
# 🛡️ GitHook Lab 02
Git hook thực chất chỉ là những file kịch bản (script) bình thường nằm ẩn trong thư mục .git/hooks/ trên máy của người tạo. Vì người tạo hiện tại có toàn quyền quản trị đối với máy tính của mình, nên người tạo có thể tự do mở file đó ra sửa nội dung, xóa nó đi, hoặc tước quyền thực thi của nó. Giống như việc ổ khóa nằm bên trong nhà và chủ nhà đang là người cầm chìa khóa vậy.

<img width="734" height="467" alt="Screenshot 2026-09-23 161900" src="https://github.com/user-attachments/assets/b154a75c-046c-4fbc-a5da-8bbe51713da1" />

# 🛡️ Báo cáo Phân tích Lỗ hổng: Secure Logger Lab

> **Mô tả:** Tài liệu Write-up phân tích và trình bày các kịch bản khai thác thử nghiệm (Proof of Concept) đối với 5 lỗ hổng bảo mật được phát hiện trong mã nguồn `secure_logger_lab`.

---

## 🐛 Chi tiết Lỗ hổng (Vulnerability Analysis)

### 1. 💉 SQL Injection (Bypass Blacklist lỏng lẻo)
* **Mô tả:** Cơ chế Sanitization sử dụng danh sách đen (Blacklist) nhưng không bao quát hết các từ khóa nguy hiểm. Các lệnh như `EXEC`, `HAVING`, `ORDER BY`, `TRUNCATE`, `ALTER`, `CREATE` hoàn toàn bị bỏ lọt.
* **Bằng chứng (PoC):** Gửi payload JSON chứa câu lệnh phá hoại:
  ```json
  {"sql": "TRUNCATE TABLE users"}
  ```
  <img width="979" height="954" alt="image" src="https://github.com/user-attachments/assets/e4eaaaaf-08ad-4495-b9e1-d81b13569fae" />

  Hệ thống không chặn mà vẫn xử lý và trả về `@{"sql="TRUNCATE TABLE users"}`. Tương tự với lệnh `DROP TABLE users`.
* **Rủi ro:** Kẻ tấn công có thể xóa toàn bộ dữ liệu, thay đổi cấu trúc Database hoặc thực thi mã độc tàn phá hệ thống.

### 2. 🌐 Server-Side Request Forgery (SSRF)
* **Mô tả:** Hàm `validate_url` trong `core.py` (dòng 8-14) chỉ kiểm tra cấu trúc URL (chứa `http/https` và `netloc`) mà không có cơ chế chặn các IP thuộc dải mạng nội bộ.
  ```json
  {"url": "[http://127.0.0.1:3306](http://127.0.0.1:3306)"}
  ```
<img width="952" height="906" alt="image" src="https://github.com/user-attachments/assets/6d625543-cdda-43fc-8b72-d03a7af42749" />


  Hệ thống trả về `True`, cho phép truy cập.
* **Rủi ro:** Kẻ gian có thể mượn danh máy chủ để quét các dịch vụ nội bộ (port 3306 của Database), hoặc trích xuất Cloud Metadata (AWS IAM, v.v.).

### 3. 🕵️ Lộ lọt Dữ liệu Nhạy cảm (PII Data Leakage)
* **Mô tả:** Lớp `SecureRotatingFileHandler` chỉ được lập trình để che giấu (mask) Email và Token, bỏ sót hoàn toàn các dữ liệu định danh cá nhân (PII) cốt lõi như số điện thoại, CMND/CCCD, hay số thẻ tín dụng.
* **Bằng chứng (PoC):** Gửi log chứa dữ liệu nhạy cảm:
  ```json
  {"sql": "SDT 0901234567 CMND 079123456789"}
  ```
<img width="951" height="918" alt="image" src="https://github.com/user-attachments/assets/5a705eb8-d43b-40ef-95b3-00bef8754371" />
<img width="964" height="877" alt="image" src="https://github.com/user-attachments/assets/fc833b89-9009-466c-8262-5ae085eee94f" />

  Kiểm tra file `secure.log`, các thông tin này bị ghi lại dưới dạng nguyên bản (plaintext) mà không hề có dấu `*` che mờ.
* **Rủi ro:** Vi phạm nghiêm trọng các quy chuẩn bảo mật dữ liệu quốc tế (GDPR, PCI-DSS).

### 4. 🧩 Phá vỡ tính Toàn vẹn của Log (Log Integrity Failure)
* **Mô tả:** Cơ chế chống giả mạo bằng chữ ký số/hàm băm (hash) bị lỗi logic khi ghi file. Các mã hash bị ghi nối tiếp nhau liên tục mà không có ký tự ngắt dòng.
* **Bằng chứng (PoC):** Mở file chữ ký `secure.log.sig`, quản trị viên chỉ thấy một chuỗi Hex dài vô tận (VD: `23a831e59...7d4400d4...`) không thể đọc được.
* **Rủi ro:** Không thể bóc tách mã băm để đối chiếu cho từng dòng log riêng biệt. Việc kiểm chứng tính toàn vẹn thất bại, kẻ gian có thể sửa log mà không để lại dấu vết.
<img width="976" height="1006" alt="image" src="https://github.com/user-attachments/assets/13e4d7d3-0a41-4a7a-9223-076475236e06" />


### 5. 📦 Content-Type Smuggling (Bypass WAF)
* **Mô tả:** Hệ thống Backend dễ dãi trong việc phân tích cú pháp (parse). Nó cố gắng đọc nội dung Body dưới dạng JSON bất chấp Client khai báo định dạng gì ở Header.
* **Bằng chứng (PoC):** Gửi request với Header khai báo văn bản thuần:
  ```powershell
  Invoke-RestMethod -Method POST -ContentType "text/plain" -Body '{"sql":"DROP TABLE users"}'
  ```
  <img width="951" height="918" alt="image" src="https://github.com/user-attachments/assets/efca0b8c-fd82-4718-b012-6f688d598bb3" />

  Hệ thống vẫn parse thành công JSON và xử lý câu lệnh SQL bên trong.
* **Rủi ro:** Vượt qua các hệ thống Tường lửa (WAF) cũ vốn chỉ quét mã độc JSON khi Header khai báo đúng là `application/json`.
* **Cách vá (Remediation):** Áp dụng *Strict Content-Type Validation*. Từ chối xử lý và trả về mã lỗi `HTTP 415 Unsupported Media Type` nếu Header không khớp với định dạng Body.

---
