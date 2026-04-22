import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh

def generate_keys():
    print("Generating keys...")
    parameters = dh.generate_parameters(generator=2, key_size=512)
    private_key1 = parameters.generate_private_key()
    public_key1 = private_key1.public_key()

    private_key2 = parameters.generate_private_key()
    public_key2 = private_key2.public_key()

    shared_key1 = private_key1.exchange(public_key2)
    shared_key2 = private_key2.exchange(public_key1)
    return shared_key1, shared_key2

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
