import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
import sys

def get_parameters():
    return dh.generate_parameters(generator=2, key_size=512)

def generate_keys(parameters):
    print("Generating keys...")
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_shared_secret(private_key, public_key):
    shared_key = private_key.exchange(public_key)
    return shared_key

def derive_key(shared_key, salt: bytes):
    key = hashlib.pbkdf2_hmac('sha256', shared_key, salt, 100000)
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
