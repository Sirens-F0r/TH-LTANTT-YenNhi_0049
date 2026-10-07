# YenNhi_0049
# BUOI 1
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

#BUOI 2
# 🔐 Crypto-Toolkit — Bài thực hành 2: Mã hoá, Triển khai PKI

> Môn: An toàn thông tin | HUTECH University

## 📌 Mô tả

Xây dựng thư viện mật mã `securecrypto` với các chức năng:
- **AES**: Mã hoá / Giải mã file bằng AES-GCM + PBKDF2
- **RSA**: Tạo cặp khoá, Ký số, Xác minh chữ ký
- **Hash**: Băm mật khẩu bằng Argon2

Toolkit hỗ trợ 3 cách sử dụng: **CLI**, **GUI (Tkinter)**, **API (Flask)**.

## 📁 Cấu trúc thư mục

```
crypto-toolkit/
├── securecrypto/
│   ├── __init__.py
│   ├── aes_utils.py        # Mã hoá AES-GCM
│   ├── rsa_utils.py         # Ký số RSA
│   ├── hash_utils.py        # Băm password Argon2
│   ├── cli.py               # Giao diện dòng lệnh
│   ├── app_gui.py           # Giao diện đồ hoạ Tkinter
│   └── api.py               # REST API Flask
├── tests/
│   ├── test_aes_utils.py
│   ├── test_hash_utils.py
│   └── test_rsa_utils.py
├── files/
│   └── data.txt             # File mẫu để test
├── exploit_path_traversal.py # Script demo khai thác lỗ hổng
├── setup.py
└── requirements.txt
```

## ⚙️ Cài đặt

```bash
cd crypto-toolkit
pip install -e .
pip install pytest requests
```

## 🚀 Cách sử dụng

### CLI
```bash
# Mã hoá
python -m securecrypto.cli --encrypt .\files\data.txt --password pass123

# Giải mã (dùng chuỗi Key trả về từ lệnh encrypt)
python -m securecrypto.cli --decrypt .\files\data.txt.enc --password <chuỗi_key_base64>
```

### GUI
```bash
python securecrypto/app_gui.py
```

### API
```bash
# Bật server
python securecrypto/api.py

# Test encrypt bằng curl
curl -X POST http://127.0.0.1:5000/encrypt -F "file=@files/data.txt" -F "password=pass123"
```

## ✅ Chạy Unit Tests

```bash
python -m pytest tests/ -v -s
```

Kết quả: **15 passed** (6 test gốc + 9 test bypass lỗ hổng bảo mật)

## 🔴 Phân tích lỗ hổng bảo mật

Sau khi hoàn thành bài thực hành, mình tiến hành kiểm tra bảo mật và phát hiện **12 lỗ hổng**, trong đó có **4 lỗi nghiêm trọng**.

### Lỗ hổng nghiêm trọng

| # | File | Lỗ hổng | Giải thích |
|---|------|---------|------------|
| 1 | `api.py:15` | **Path Traversal** | Hacker gửi file có tên `../../../etc/passwd` để ghi đè file bất kỳ trên server. Nguyên nhân: không dùng `secure_filename()` lọc tên file |
| 2 | `api.py:18` | **Key lộ qua HTTP** | API trả key mã hoá qua HTTP (không mã hoá), ai sniff mạng cũng đọc được |
| 3 | `aes_utils.py:27` | **Key trả ra ngoài dạng plaintext** | Hàm encrypt trả key thẳng ra ngoài. Ai có chuỗi key này đều giải mã được file mà không cần biết password |
| 4 | `aes_utils.py:35` | **Decrypt bỏ qua password** | Hàm decrypt nhận key trực tiếp thay vì yêu cầu nhập lại password rồi tự tính toán key |

### Lỗ hổng mức cao

| # | File | Lỗ hổng | Giải thích |
|---|------|---------|------------|
| 5 | `api.py:27` | **Lộ đường dẫn server** | API trả về đường dẫn tuyệt đối, hacker biết được cấu trúc thư mục server |
| 6 | `api.py:30` | **Không có authentication** | Ai cũng gọi được API, không cần đăng nhập |
| 7 | `rsa_utils.py:17` | **except Exception nuốt mọi lỗi** | Che giấu bug nghiêm trọng, truyền sai kiểu dữ liệu cũng im lặng trả về False |

### Lỗ hổng mức trung bình

| # | File | Lỗ hổng | Giải thích |
|---|------|---------|------------|
| 8 | `cli.py:8` | **Password lộ trong command history** | Gõ password trực tiếp trên terminal → lưu lại trong lịch sử lệnh |
| 9 | `aes_utils.py:17` | **Không kiểm tra độ mạnh password** | Password rỗng `""` vẫn mã hoá thành công |
| 10 | `hash_utils.py:4` | **Chấp nhận password yếu** | Password `"1"`, `"a"` đều hash OK, không có chính sách password |
| 11 | `hash_utils.py` | **Thiếu hàm verify** | Chỉ có hash, không cung cấp verify → người dùng tự viết dễ sai |
| 12 | `rsa_utils.py:10` | **Dùng PKCS1v15** | Thuật toán padding cũ, dễ bị tấn công Bleichenbacher |

## 💣 Demo khai thác Path Traversal

```bash
# Terminal 1: Bật API server
python securecrypto/api.py

# Terminal 2: Chạy script tấn công
python exploit_path_traversal.py
```

Kết quả: Script chứng minh hacker có thể **ghi đè file bất kỳ** trên server chỉ bằng cách chèn `../` vào tên file upload.

## 🛡️ Cách khắc phục

```python
# 1. Path Traversal → Dùng secure_filename
from werkzeug.utils import secure_filename
filename = secure_filename(f.filename)

# 2. Key không nên trả ra ngoài → Decrypt phải nhận password, tự tính key
def decrypt_file_aes(encrypted_file, password):  # Nhận password, không nhận key
    salt = raw[:16]
    key = derive_key_from_password(password, salt)  # Tự tính key từ password + salt

# 3. Validate password
if len(password) < 8:
    raise ValueError("Password phai co it nhat 8 ky tu")

# 4. RSA nên dùng PSS thay vì PKCS1v15
padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

# 5. except Exception → Chỉ bắt lỗi cụ thể
except InvalidSignature:
    return False
```
<img width="497" height="305" alt="image" src="https://github.com/user-attachments/assets/1e5c5073-1bbd-4cfe-82dc-35584781a0e1" />
<img width="497" height="302" alt="image" src="https://github.com/user-attachments/assets/3eee5866-07de-4de6-ac35-de43faf32591" />
<img width="493" height="362" alt="image" src="https://github.com/user-attachments/assets/b9e115b2-214d-420b-8e5c-f6c14817dfa3" />

# 🪪 Mini Certificate Authority (mini-ca)

> Môn: An toàn thông tin | HUTECH University

## 📌 Mô tả

Xây dựng hệ thống Chứng thực Chữ ký số (Certificate Authority - CA) đơn giản sử dụng Python và thư viện `cryptography`. 
Dự án mô phỏng toàn bộ quy trình PKI:
- Tạo Root CA và Intermediate CA.
- Phát hành chứng chỉ (Issue Certificate) cho người dùng cuối (End-entity).
- Xác minh chuỗi chứng chỉ (Certificate Chain Verification).
- Thu hồi chứng chỉ (Revocation / CRL).
- Kiểm tra trạng thái chứng chỉ qua CRL (Mô phỏng OCSP).

## 📁 Cấu trúc thư mục

```
mini-ca/
├── ca_utils.py           # Logic tạo CA, ký và xác minh chứng chỉ
├── revoke_utils.py       # Logic thu hồi chứng chỉ và kiểm tra CRL
├── demo.py               # Chạy kịch bản CA qua dòng lệnh (CLI)
├── demo_ui.py            # Giao diện đồ họa (Tkinter) mô phỏng CA
├── requirements.txt      # Chứa các thư viện cần thiết
└── tests/
    └── test_security.py  # Unit Test chứng minh lỗ hổng bảo mật
```

## ⚙️ Cài đặt

```bash
cd mini-ca
pip install -r requirements.txt
pip install pytest
```

## 🚀 Cách sử dụng

### Chạy kịch bản tự động (CLI)
Kịch bản tự động thực hiện: Tạo Root CA -> Tạo Intermediate CA -> Cấp chứng chỉ User -> Verify -> Thu hồi -> Kiểm tra trạng thái thu hồi.
```bash
python demo.py
```

### Chạy Giao diện đồ họa (GUI)
```bash
python demo_ui.py
```

## 🔴 Phân tích Lỗ hổng Bảo mật (Vulnerability Analysis)

Mặc dù hệ thống CA chạy thành công về mặt chức năng, tuy nhiên mã nguồn (được tham khảo từ tài liệu thực hành) đang bỏ qua rất nhiều quy chuẩn bảo mật bắt buộc của X.509, dẫn đến **4 lỗ hổng nghiêm trọng**:

| Lỗ hổng | Vị trí | Mô tả chi tiết & Mức độ nguy hiểm |
|---------|--------|-----------------------------------|
| **Lưu Khóa riêng ở dạng rõ (Plaintext)** | `ca_utils.py` (hàm `save_key`) | Private Key của Root CA và Intermediate CA được lưu thành file mà không có mật khẩu bảo vệ (`NoEncryption()`). Hacker chiếm được file là có thể giả mạo CA phát hành chứng chỉ tùy ý. |
| **Xác thực chứng chỉ bỏ qua thời hạn** | `ca_utils.py` (hàm `verify_certificate_chain`) | Hàm chỉ kiểm tra chữ ký số mà không kiểm tra `not_valid_before` hay `not_valid_after`. **Chứng chỉ hết hạn vẫn được coi là hợp lệ!** |
| **Lỗ hổng leo thang đặc quyền (Bypass Basic Constraints)** | `ca_utils.py` (hàm `verify_certificate_chain`) | Không kiểm tra cờ `CA=True`. Nghĩa là một User bình thường có thể dùng chứng chỉ của mình để cấp phát chứng chỉ cho người khác, và hàm xác minh vẫn sẽ báo hợp lệ. |
| **Kiểm tra CRL thiếu xác minh chữ ký** | `revoke_utils.py` (hàm `check_revocation_status`) | Đọc file CRL và tin tưởng ngay lập tức nội dung bên trong mà không kiểm tra chữ ký của file CRL đó. Hacker có thể tráo file CRL rỗng để phục hồi chứng chỉ đã bị thu hồi. |

## 🛡️ Kiểm chứng lỗ hổng (Defensive Security Tests)

Dự án đã đính kèm các kịch bản kiểm thử bảo mật bằng `pytest` để chứng minh lỗ hổng trong logic xác minh.

Chạy kiểm tra:
```bash
python -m pytest tests/test_security.py -v -s
```

**Kết quả:** 2/2 tests sẽ báo **FAILED** ❌, chứng minh hệ thống đang chấp nhận những hành vi sai trái:
1. `test_verify_rejects_expired_certificate`: Đưa vào chứng chỉ hết hạn -> Hàm vẫn báo hợp lệ.
2. `test_verify_rejects_unauthorized_issuer`: Đưa vào chứng chỉ do User thường tự cấp -> Hàm vẫn báo hợp lệ.

## 🛠️ Hướng dẫn Khắc phục (Remediation)

Để hệ thống CA đạt tiêu chuẩn an toàn, cần sửa đổi mã nguồn như sau:

**1. Bảo vệ Khóa Riêng:**
Sử dụng `BestAvailableEncryption` thay vì `NoEncryption` khi lưu file `.pem`.
```python
encryption_algorithm=serialization.BestAvailableEncryption(b"mat-khau-sieu-kho")
```

**2. Sửa hàm `verify_certificate_chain`:**
Phải kiểm tra đầy đủ thời gian và quyền hạn (extensions):
```python
import datetime

# Kiểm tra hạn sử dụng
now = datetime.datetime.utcnow()
if not (cert_to_verify.not_valid_before <= now <= cert_to_verify.not_valid_after):
    raise ValueError("Chứng chỉ đã hết hạn hoặc chưa có hiệu lực!")

# Kiểm tra quyền làm CA của issuer
basic_constraints = issuer_cert.extensions.get_extension_for_class(x509.BasicConstraints)
if not basic_constraints.value.ca:
    raise ValueError("Chứng chỉ cấp trên không có quyền CA!")
```

**3. Xác minh chữ ký của CRL:**
Trước khi duyệt qua danh sách chứng chỉ bị thu hồi, phải lấy public key của CA để `.verify()` chữ ký của file CRL.
<img width="888" height="295" alt="image" src="https://github.com/user-attachments/assets/e7a3b850-29bf-4c9b-b01c-5f712bf467d9" />

#Lab03
# NetRecon - Network Reconnaissance Toolkit

## Mô tả
**NetRecon** là bộ công cụ trinh sát mạng (network reconnaissance) tích hợp nhiều chức năng quét và phân tích mạng. Hỗ trợ cả giao diện dòng lệnh (CLI) và giao diện web (Flask).

## Cấu trúc thư mục

```
netrecon/
├── modules/                     # Các module chức năng
│   ├── __init__.py
│   ├── port_scanner.py          # Quét cổng (async)
│   ├── service_detector.py      # Nhận diện dịch vụ (nmap)
│   ├── banner_grabber.py        # Thu thập banner
│   ├── network_mapper.py        # Bản đồ mạng (ARP)
│   ├── vuln_checker.py          # Kiểm tra lỗ hổng CVE
│   ├── filter_utils.py          # Lọc IP (whitelist/blacklist)
│   └── email_sender.py          # Gửi kết quả qua email
├── templates/                   # Giao diện web (Jinja2)
│   ├── layout.html              # Template chính
│   ├── index.html               # Trang chủ (form nhập)
│   └── result.html              # Trang kết quả
├── static/
│   └── style.css                # CSS giao diện
├── app.py                       # Flask web server
├── cli.py                       # Giao diện dòng lệnh (Click)
├── requirements.txt             # Danh sách thư viện
├── .env                         # Cấu hình SMTP (không push lên Git)
└── .gitignore                   # File bỏ qua khi push Git
```

## Công nghệ sử dụng

| Công nghệ | Mục đích |
|-----------|----------|
| **Python 3** | Ngôn ngữ lập trình chính |
| **Flask** | Web framework cho giao diện web |
| **Click** | Framework xây dựng CLI |
| **asyncio** | Quét cổng bất đồng bộ (async) |
| **Nmap** | Nhận diện dịch vụ mạng |
| **HTMX** | Cập nhật kết quả động trên web |
| **python-dotenv** | Quản lý biến môi trường (.env) |
| **smtplib** | Gửi email kết quả qua Gmail SMTP |

## Cách cài đặt & chạy

### 1. Cài đặt thư viện
```bash
pip install -r requirements.txt
```

### 2. Cấu hình email
Tạo file `.env` trong thư mục `netrecon/`:
```
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
```
> **Lưu ý**: Sử dụng **App Password** của Google, không phải mật khẩu tài khoản thông thường.

### 3. Chạy bằng CLI
```bash
python cli.py --target 127.0.0.1 --ports 22,80,443 --mode all
```

**Các tùy chọn CLI:**

| Tham số | Mô tả | Mặc định |
|---------|--------|----------|
| `--target` | Địa chỉ IP mục tiêu | *(bắt buộc)* |
| `--ports` | Danh sách cổng (phân cách bằng dấu phẩy) | `22,80,443` |
| `--rate-limit` | Số lượng quét đồng thời tối đa | `100` |
| `--mode` | Chế độ quét | `all` |

**Các chế độ quét (mode):**
- `scan` - Quét cổng mở
- `service` - Nhận diện dịch vụ
- `banner` - Thu thập banner
- `map` - Bản đồ mạng
- `vuln` - Kiểm tra lỗ hổng
- `all` - Tất cả các chế độ

### 4. Chạy bằng Web
```bash
python app.py
```
Mở trình duyệt truy cập: `http://127.0.0.1:5000/`

## Mô tả các module

### `port_scanner.py`
- Sử dụng **asyncio** để quét cổng bất đồng bộ
- Hỗ trợ **rate limiting** với `asyncio.Semaphore` để giới hạn số kết nối đồng thời
- Ghi log kết quả vào file `netrecon.log`

### `service_detector.py`
- Sử dụng **Nmap** (`nmap -sV`) để nhận diện dịch vụ đang chạy trên các cổng mở
- Trả về tên dịch vụ, phiên bản phần mềm

### `banner_grabber.py`
- Kết nối trực tiếp đến cổng và đọc banner response
- Timeout 2 giây để tránh treo kết nối
- Ghi log banner thu thập được

### `network_mapper.py`
- Sử dụng lệnh `arp -a` để liệt kê các thiết bị trong mạng LAN
- Hiển thị IP, MAC address và loại kết nối

### `vuln_checker.py`
- Kiểm tra các cổng mở dựa trên danh sách CVE đã biết:
  - Port 21 (FTP): CVE-2015-3306, CVE-2001-0261
  - Port 22 (SSH): CVE-2018-15473
  - Port 23 (Telnet): CVE-2011-4862
  - Port 80 (HTTP): CVE-2021-41773
  - Port 443 (HTTPS): CVE-2021-3449

### `filter_utils.py`
- Lọc danh sách IP theo **whitelist** (chỉ cho phép) hoặc **blacklist** (loại trừ)

### `email_sender.py`
- Gửi kết quả quét qua email sử dụng Gmail SMTP (TLS, port 587)
- Đọc thông tin đăng nhập từ file `.env`

### `app.py` (Web Interface)
- Trang chủ (`/`): Form nhập thông tin quét
- Trang kết quả (`/scan`): Hiển thị kết quả và gửi email

### `cli.py` (Command Line Interface)
- Sử dụng thư viện **Click** để tạo giao diện dòng lệnh chuyên nghiệp
- Hỗ trợ tất cả các chế độ quét

## Kết quả mẫu

### CLI Output
```
$ python cli.py --target 127.0.0.1

Starting Nmap 7.991 ( https://nmap.org )
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00s latency).

PORT     STATE  SERVICE VERSION
22/tcp   closed ssh
80/tcp   closed http
443/tcp  closed https

{22: 'SSH - CVE-2018-15473', 80: 'HTTP - CVE-2021-41773', 443: 'HTTPS - CVE-2021-3449'}
```

### Web Interface
Giao diện web cho phép:
- Nhập IP mục tiêu và danh sách cổng
- Chọn chế độ quét (All, Port Scan, Service Detection, Banner Grab, Network Map, Vulnerability Check)
- Nhập email để nhận kết quả
- Hiển thị kết quả trực tiếp trên trang web

## Bảo mật

- File `.env` chứa thông tin nhạy cảm được thêm vào `.gitignore`
- Không push chứng chỉ (`certs/`, `*.pem`) lên Git
- Sử dụng App Password thay vì mật khẩu tài khoản Google
<img width="501" height="154" alt="Screenshot 2026-10-07 135216" src="https://github.com/user-attachments/assets/33efa8aa-0a82-4fb9-8de3-941ff7c9281f" />
<img width="511" height="149" alt="Screenshot 2026-10-07 135205" src="https://github.com/user-attachments/assets/4a980f53-a714-45bf-8247-b77812fb3e3b" />

# Secure Chat - Ứng dụng Chat Bảo Mật

## Mô tả
Ứng dụng chat client-server sử dụng **TLS/SSL** để mã hóa kênh truyền và **AES-256-CBC** để mã hóa nội dung tin nhắn. Hệ thống yêu cầu chứng chỉ số (X.509) cho cả server và client (mutual TLS authentication).

## Cấu trúc thư mục

```
secure-chat/
├── certs/                    # Thư mục chứa chứng chỉ số
│   ├── ca/                   # Certificate Authority
│   │   ├── ca.key            # Private key CA
│   │   └── ca.crt            # Certificate CA
│   ├── server/               # Chứng chỉ Server
│   │   ├── server.key
│   │   ├── server.csr
│   │   └── server.crt
│   └── client/               # Chứng chỉ Client
│       ├── client.key
│       ├── client.csr
│       └── client.crt
├── openssl.cnf               # Cấu hình OpenSSL cho CA
├── make-certs.bat            # Script tự động tạo chứng chỉ
├── message_encryption.py     # Module mã hóa/giải mã AES-256-CBC
├── connection_manager.py     # Quản lý kết nối client
├── room_manager.py           # Quản lý phòng chat
├── server.py                 # Server TLS
└── client.py                 # Client TLS
```

## Công nghệ sử dụng

| Công nghệ | Mục đích |
|-----------|----------|
| **Python 3** | Ngôn ngữ lập trình chính |
| **TLS 1.2+** | Mã hóa kênh truyền (transport layer) |
| **AES-256-CBC** | Mã hóa nội dung tin nhắn (application layer) |
| **X.509 Certificates** | Xác thực danh tính server và client |
| **OpenSSL** | Tạo và quản lý chứng chỉ số |
| **cryptography** | Thư viện mã hóa Python |

## Cách cài đặt & chạy

### 1. Cài đặt thư viện
```bash
pip install cryptography
```

### 2. Tạo chứng chỉ số
Chạy script `make-certs.bat` để tự động sinh chứng chỉ CA, Server và Client:
```bash
.\make-certs.bat
```

### 3. Chạy Server
```bash
python server.py
```
Server sẽ lắng nghe trên `127.0.0.1:8443`.

### 4. Chạy Client
Mở terminal mới và chạy:
```bash
python client.py
```
Nhập username và bắt đầu chat.

## Mô tả các module

### `openssl.cnf`
File cấu hình OpenSSL để tạo chứng chỉ CA (Certificate Authority) với các thông tin:
- **Country**: VN
- **State/Locality**: HN
- **Organization**: MyOrg
- **Common Name**: MyRootCA

### `make-certs.bat`
Script tự động hóa việc tạo chứng chỉ số:
- Tạo CA root certificate (tự ký, hạn 10 năm)
- Tạo Server certificate (ký bởi CA, hạn 1 năm)
- Tạo Client certificate (ký bởi CA, hạn 1 năm)

### `message_encryption.py`
Class `MessageEncryption` cung cấp:
- **encrypt(plaintext)**: Mã hóa tin nhắn bằng AES-256-CBC với IV ngẫu nhiên và PKCS7 padding
- **decrypt(ciphertext)**: Giải mã tin nhắn

### `connection_manager.py`
Class `ConnectionManager` quản lý danh sách client đang kết nối:
- Lưu trữ socket, username và encryption key của mỗi client
- Thread-safe với threading.Lock()

### `room_manager.py`
Class `RoomManager` quản lý các phòng chat:
- Tạo/tham gia/rời phòng
- Broadcast tin nhắn trong phòng

### `server.py`
- Tạo SSL context yêu cầu chứng chỉ client (mutual TLS)
- Chỉ chấp nhận TLS 1.2 trở lên
- Nhận AES key từ client, mã hóa lại tin nhắn theo key riêng của từng client trước khi gửi

### `client.py`
- Kết nối TLS đến server với chứng chỉ client
- Tạo AES-256 key ngẫu nhiên và gửi cho server
- Gửi/nhận tin nhắn được mã hóa AES

## Luồng hoạt động

```
Client A                    Server                     Client B
   |                          |                          |
   |--- TLS Handshake ------->|                          |
   |    (mutual auth)         |                          |
   |                          |<--- TLS Handshake -------|
   |                          |     (mutual auth)        |
   |--- username:AES_key ---->|                          |
   |                          |<--- username:AES_key ----|
   |                          |                          |
   |--- AES_encrypt(msg) ---->|                          |
   |                          |--- AES_encrypt(msg) ---->|
   |                          |    (re-encrypted with    |
   |                          |     Client B's key)      |
```

## Bảo mật

- **Transport Layer**: TLS 1.2+ với mutual authentication
- **Application Layer**: AES-256-CBC encryption
- **Key Exchange**: Mỗi client có AES key riêng, server re-encrypt tin nhắn theo key của người nhận
- **Certificate Validation**: Cả server và client đều phải có chứng chỉ hợp lệ do CA cấp
<img width="386" height="334" alt="Screenshot 2026-10-07 152352" src="https://github.com/user-attachments/assets/01ea0ffd-fa3e-436e-9d9b-5daf1f5bcbc6" />
<img width="509" height="109" alt="Screenshot 2026-10-07 152413" src="https://github.com/user-attachments/assets/f1028fec-fb2a-4fb7-b6e0-c5750d804cfb" />
<img width="432" height="471" alt="Screenshot 2026-10-07 152513" src="https://github.com/user-attachments/assets/9a60eaaa-0d0e-4765-b0be-c0c03112936d" />


