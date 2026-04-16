import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password: str, salt: bytes):
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key

def encrypt(key: bytes, plaintext: str):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext

def decrypt(key: bytes, data: bytes):
    aesgcm = AESGCM(key)
    nonce = data[:12]
    cyphtertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, cyphtertext, None)
    return plaintext.decode()
