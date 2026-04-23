import socket
from cryptography.exceptions import InvalidTag
from utils import *
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key, \
    load_der_parameters

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 10001))

param_length = int.from_bytes(client.recv(4), byteorder='big')
parameters = load_der_parameters(client.recv(param_length))

private_key, public_key = generate_keys(parameters)
udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_client.bind(('127.0.0.1', 10002))
udp_client.sendto(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), ("127.0.0.1", 10001))

salt = client.recv(16)

public_key2, _ = udp_client.recvfrom(2048)
public_key2 = load_der_public_key(public_key2)
print("Server public key: ", public_key2)

shared_secret = generate_shared_secret(private_key, public_key2)
key = derive_key(shared_secret, salt)

while True:
    data = client.recv(1024)
    if not data:
        break
    try:
        decrypted_message = decrypt(key, data)
        if decrypted_message:
            print("Server: ", decrypted_message)
            message = input("Message: ")
            if message == "exit":
                break
            client.sendall(encrypt(key, message))
        else:
            print("Authentication failed...")
    except InvalidTag as e:
        print("Authentication failed...")
        break

client.close()

