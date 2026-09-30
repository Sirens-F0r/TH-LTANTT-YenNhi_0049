import pytest
import os
import sys
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Add parent directory to path so we can import ca_utils
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ca_utils import create_root_ca, verify_certificate_chain, generate_key

def test_verify_rejects_expired_certificate():
    """LỖI 1: Hệ thống phải TỪ CHỐI chứng chỉ đã hết hạn."""
    root_key, root_cert = create_root_ca()
    
    # Tạo chứng chỉ cố tình hết hạn (hết hạn từ 1 ngày trước)
    user_key = generate_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expired User")])
    expired_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        user_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow() - datetime.timedelta(days=10)
    ).not_valid_after(
        datetime.datetime.utcnow() - datetime.timedelta(days=1) # Đã hết hạn!
    ).sign(root_key, hashes.SHA256())
    
    # Kì vọng: Hàm xác thực PHẢI nhận diện đây là chứng chỉ hết hạn và trả về False
    # Nếu hàm trả về True -> LỖI LỖI! Code không kiểm tra ngày tháng.
    is_valid = verify_certificate_chain(expired_cert, [root_cert])
    assert is_valid == False, "LỖI: Hàm xác thực đã CHẤP NHẬN chứng chỉ hết hạn!"

def test_verify_rejects_unauthorized_issuer():
    """LỖI 2: Chứng chỉ cấp bởi User bình thường (CA=False) phải bị TỪ CHỐI."""
    root_key, root_cert = create_root_ca()
    
    # 1. Phát hành một chứng chỉ User bình thường (không có quyền CA)
    user_key = generate_key()
    user_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Normal User")])
    user_cert = x509.CertificateBuilder().subject_name(user_subject).issuer_name(root_cert.subject).public_key(user_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True # CA = False
    ).sign(root_key, hashes.SHA256())
    
    # 2. Hacker dùng chứng chỉ User để tự ký phát hành một chứng chỉ giả
    fake_key = generate_key()
    fake_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Cert")])
    fake_cert = x509.CertificateBuilder().subject_name(fake_subject).issuer_name(user_cert.subject).public_key(fake_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).sign(user_key, hashes.SHA256()) # Ký bằng key của User bình thường
    
    # Kì vọng: Hàm xác thực PHẢI từ chối chuỗi [fake_cert -> user_cert -> root_cert]
    # Vì user_cert không có quyền làm CA. 
    # Nếu hàm trả về True -> LỖI: Ai cũng có thể làm CA!
    is_valid = verify_certificate_chain(fake_cert, [user_cert, root_cert])
    assert is_valid == False, "LỖI: Hàm xác thực đã CHẤP NHẬN chứng chỉ giả mạo do User tự cấp!"
