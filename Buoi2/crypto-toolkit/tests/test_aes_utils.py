import tempfile, os
import pytest
from securecrypto import aes_utils

def test_encrypt_decrypt():
    original_content = "Hello World!".encode('utf-8')
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(original_content)
        tmp_path = tmp.name
        
    try:
        encoded_key = aes_utils.encrypt_file_aes(tmp_path, "unused_password")
        encrypted_path = tmp_path + ".enc"
        assert os.path.exists(encrypted_path), "File mã hóa không tồn tại"
        decrypted_path = aes_utils.decrypt_file_aes(encrypted_path, encoded_key)
        assert os.path.exists(decrypted_path), "File giải mã không tồn tại"
        with open(decrypted_path, "rb") as f:
            decrypted_content = f.read()
        assert decrypted_content == original_content, "Nội dung không khớp"
    finally:
        for path in [tmp_path, tmp_path + ".enc", tmp_path + ".dec"]:
            if os.path.exists(path):
                os.remove(path)

# ============================================================
# BYPASS TEST: Chung minh cac ham KHONG validate input
# ============================================================

def test_bypass_encrypt_empty_password():
    """LO HONG: Ham chap nhan password rong '' ma khong bao loi.
    Hacker chi can de password rong la van ma hoa duoc file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
        tmp.write(b"Du lieu bi mat cua cong ty")
        tmp_path = tmp.name
    try:
        key = aes_utils.encrypt_file_aes(tmp_path, "")
        # Ham KHONG reject password rong => LO HONG!
        assert key is not None
        assert len(key) > 0
        print("[BYPASS] Password rong '' van ma hoa thanh cong!")
        print("  => Ham khong kiem tra do manh cua password!")
    finally:
        for p in [tmp_path, tmp_path + ".enc"]:
            if os.path.exists(p):
                os.remove(p)

def test_bypass_key_exposed_in_plaintext():
    """LO HONG: Ham tra key truc tiep ra ngoai dang plaintext (base64).
    Bat ky ai nhan duoc chuoi key nay deu giai ma duoc file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
        tmp.write(b"Thong tin tuyet mat")
        tmp_path = tmp.name
    try:
        # Ham encrypt tra KEY ra ngoai => Ai co key nay deu mo duoc file
        key = aes_utils.encrypt_file_aes(tmp_path, "MatKhauCuaToi")
        enc_path = tmp_path + ".enc"

        # Bat ky ai (ke ca nguoi khong biet password) chi can co chuoi key
        # la giai ma duoc file => KHONG CAN BIET PASSWORD!
        decrypted_path = aes_utils.decrypt_file_aes(enc_path, key)
        with open(decrypted_path, "rb") as f:
            content = f.read()
        assert content == b"Thong tin tuyet mat"
        print("[BYPASS] Giai ma thanh cong CHI BANG KEY, khong can password!")
        print("  => Key bi lo ra ngoai = mat toan bo du lieu!")
    finally:
        for p in [tmp_path, tmp_path + ".enc", tmp_path + ".dec"]:
            if os.path.exists(p):
                os.remove(p)

def test_bypass_decrypt_ignores_password():
    """LO HONG: Ham decrypt KHONG dung password ma dung key truc tiep.
    Password tro thanh vo nghia trong qua trinh giai ma."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
        tmp.write(b"Du lieu ngan hang")
        tmp_path = tmp.name
    try:
        # Ma hoa voi password "SuperSecret123!"
        key = aes_utils.encrypt_file_aes(tmp_path, "SuperSecret123!")
        enc_path = tmp_path + ".enc"

        # Giai ma KHONG CAN BIET password "SuperSecret123!"
        # Chi can co chuoi key la du => Password la vo nghia!
        decrypted_path = aes_utils.decrypt_file_aes(enc_path, key)
        with open(decrypted_path, "rb") as f:
            content = f.read()
        assert content == b"Du lieu ngan hang"
        print("[BYPASS] Giai ma KHONG CAN password goc!")
        print("  => Thiet ke sai: decrypt phai yeu cau nhap lai password")
        print("  => roi tu tinh toan key, thay vi nhan key truc tiep!")
    finally:
        for p in [tmp_path, tmp_path + ".enc", tmp_path + ".dec"]:
            if os.path.exists(p):
                os.remove(p)
