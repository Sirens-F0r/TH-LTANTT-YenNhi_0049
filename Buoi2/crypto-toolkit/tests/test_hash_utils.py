import pytest
from securecrypto import hash_utils
from argon2.exceptions import VerifyMismatchError
from argon2 import PasswordHasher

def test_hash_password_and_verify():
    password = "strongPassword123!"
    hashed = hash_utils.hash_password_secure(password)
    assert hashed is not None
    
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    try:
        ph.verify(hashed, password)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified == True

def test_wrong_password_verification():
    password = "CorrectPass"
    wrong_password = "WrongPass"
    hashed = hash_utils.hash_password_secure(password)
    
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    try:
        ph.verify(hashed, wrong_password)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified == False

# ============================================================
# BYPASS TEST: Chung minh ham hash KHONG validate input
# ============================================================

def test_bypass_hash_empty_password():
    """LO HONG: Hash password rong '' => Ham van chap nhan!
    He thong cho phep nguoi dung dat password rong."""
    hashed = hash_utils.hash_password_secure("")
    assert hashed is not None
    # Kiem tra hash van hop le => He thong KHONG co chinh sach password!
    ph = PasswordHasher()
    ph.verify(hashed, "")  # Verify thanh cong voi password rong
    print("[BYPASS] Password rong '' duoc chap nhan va hash thanh cong!")
    print("  => Khong co kiem tra do dai/do manh password!")

def test_bypass_hash_weak_password():
    """LO HONG: Password yeu '1' van duoc chap nhan binh thuong.
    Khong co bat ky kiem tra nao ve do manh cua password."""
    weak_passwords = ["1", "a", "123", "abc"]
    for pwd in weak_passwords:
        hashed = hash_utils.hash_password_secure(pwd)
        assert hashed is not None
    print(f"[BYPASS] Tat ca {len(weak_passwords)} password yeu deu duoc chap nhan!")
    print("  => Ham khong kiem tra: do dai, chu hoa, so, ky tu dac biet!")

def test_bypass_hash_no_verify_function():
    """LO HONG: Thu vien chi co ham hash, KHONG co ham verify.
    Nguoi dung phai tu viet logic verify => De sai."""
    password = "MyPassword"
    hashed = hash_utils.hash_password_secure(password)

    # Muon verify phai tu import PasswordHasher va tu lam
    # => De bi sai, de bi bo qua buoc verify
    assert not hasattr(hash_utils, 'verify_password'), \
        "Thu vien KHONG cung cap ham verify_password!"
    print("[BYPASS] Thu vien KHONG co ham verify_password!")
    print("  => Nguoi dung phai tu viet => De mac loi bao mat!")
