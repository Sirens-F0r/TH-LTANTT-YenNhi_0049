import pytest
from securecrypto import rsa_utils

def test_rsa_keypair_generation():
    priv, pub = rsa_utils.generate_rsa_keypair()
    assert priv is not None
    assert pub is not None

def test_sign_and_verify():
    priv, pub = rsa_utils.generate_rsa_keypair()
    data = b"Test data for signing"
    signature = rsa_utils.sign_data_rsa(data, priv)
    assert rsa_utils.verify_signature_rsa(data, signature, pub) == True

def test_verify_invalid_signature():
    priv, pub = rsa_utils.generate_rsa_keypair()
    data = b"Test data"
    signature = rsa_utils.sign_data_rsa(data, priv)
    tampered_data = b"Tampered data"
    assert rsa_utils.verify_signature_rsa(tampered_data, signature, pub) == False

# ============================================================
# BYPASS TEST: Chung minh cac ham RSA KHONG validate input
# ============================================================

def test_bypass_verify_catches_all_exceptions():
    """LO HONG: except Exception nuot tat ca loi => Che giau bug!
    
    Ham verify_signature_rsa dung 'except Exception' nen bat ke 
    loi gi xay ra (key sai kieu, data la None...) no deu tra ve False
    thay vi bao loi. Dieu nay che giau bug rat nguy hiem."""
    priv, pub = rsa_utils.generate_rsa_keypair()
    
    # Truyen None lam data => Dang le phai bao loi "data khong hop le",
    # nhung vi 'except Exception' nen no im lang tra ve False
    result = rsa_utils.verify_signature_rsa(None, b"fake_sig", pub)
    assert result == False
    print("[BYPASS] verify(None, ...) => Tra ve False thay vi bao loi!")
    print("  => 'except Exception' che giau moi loi, ke ca bug nghiem trong!")

    # Truyen so nguyen lam signature => Cung bi nuot loi
    result2 = rsa_utils.verify_signature_rsa(b"data", 12345, pub)
    assert result2 == False
    print("[BYPASS] verify(data, 12345, ...) => False thay vi bao loi!")

def test_bypass_verify_wrong_key_type():
    """LO HONG: Truyen private_key vao cho verify (thay vi public_key).
    Ham im lang tra ve False thay vi canh bao nguoi dung dang dung sai key."""
    priv, pub = rsa_utils.generate_rsa_keypair()
    data = b"Test data"
    signature = rsa_utils.sign_data_rsa(data, priv)
    
    # Truyen PRIVATE key vao cho vi tri public_key => SAI hoan toan
    # Nhung ham van tra ve False thay vi bao "Ban dang dung sai loai key!"
    result = rsa_utils.verify_signature_rsa(data, signature, priv)
    assert result == False
    print("[BYPASS] verify voi private_key thay vi public_key => Im lang False!")
    print("  => Nguoi dung khong biet minh dung sai key!")

def test_bypass_private_key_not_protected():
    """LO HONG: Private key duoc tra ve truc tiep dang object trong bo nho.
    Khong co co che bao ve, ma hoa, hay gioi han truy cap key."""
    priv, pub = rsa_utils.generate_rsa_keypair()
    
    # Private key nam tran trong bo nho, ai cung truy cap duoc
    # Trong thuc te, private key phai duoc luu trong file .pem co mat khau
    # hoac trong thiet bi phan cung (HSM)
    assert priv is not None
    assert pub is not None
    
    # Co the ky bat ky du lieu gi voi private key ma khong can xac thuc
    signature = rsa_utils.sign_data_rsa(b"bat ky du lieu gi", priv)
    assert signature is not None
    print("[BYPASS] Private key khong duoc bao ve!")
    print("  => Ai co quyen truy cap bo nho deu doc duoc private key!")
    print("  => Khong co xac thuc truoc khi ky du lieu!")
