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
