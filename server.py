import socket
from cryptography.exceptions import InvalidTag
from utils import *
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

HOST = '127.0.0.1'
PORT = 10001

# Opsætning af Socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

conn, addr = server_socket.accept()
print('Connected to ', addr)

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind((HOST, PORT))

private_key, public_key = generate_keys()

# Generere salt
salt = os.urandom(16)
conn.sendall(salt)

public_key2, _ = udp_socket.recvfrom(2048)
#public_key2 = load_der_public_key(public_key2)
print("Client public key: ", public_key2)

udp_socket.sendto(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), (HOST, PORT))


shared_secret = generate_shared_secret(private_key, public_key2)
key = derive_key(shared_secret, salt)
print("Key derived! Start chatting, write 'exit' to quit")

while True:
    try:
        message = input("You: ")
        if message.lower() == "exit":
            break
        conn.sendall(encrypt(key, message))

        data = conn.recv(1024)
        if not data:
            break
        print("Client: " + decrypt(key, data))
    except InvalidTag:
        print("Incorrect key...")
        break
conn.close()
server_socket.close()

