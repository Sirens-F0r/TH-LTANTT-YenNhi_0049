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
