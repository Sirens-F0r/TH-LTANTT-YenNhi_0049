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
<img width="1414" height="931" alt="image" src="https://github.com/user-attachments/assets/ccf7b393-2c64-499a-906e-397874f56ce1" />
<img width="1390" height="697" alt="image" src="https://github.com/user-attachments/assets/c36071be-a5ef-4dff-8d22-c87d74459b79" />

```bash
python -m unittest discover tests
```
# 🛡️ GitHook Lab 02
Git hook thực chất chỉ là những file kịch bản (script) bình thường nằm ẩn trong thư mục .git/hooks/ trên máy của người tạo. Vì người tạo hiện tại có toàn quyền quản trị đối với máy tính của mình, nên người tạo có thể tự do mở file đó ra sửa nội dung, xóa nó đi, hoặc tước quyền thực thi của nó. Giống như việc ổ khóa nằm bên trong nhà và chủ nhà đang là người cầm chìa khóa vậy.

<img width="1468" height="934" alt="image" src="https://github.com/user-attachments/assets/3893f497-3f8a-4586-84ad-cc6574eda4a0" />
