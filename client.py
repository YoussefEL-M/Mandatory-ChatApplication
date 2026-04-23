import socket
from cryptography.exceptions import InvalidTag
from utils import *
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

private_key, public_key = generate_keys()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 10001))

udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_client.sendto(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), ("127.0.0.1", 10001))

salt = client.recv(16)

# -TODO Do not send shared secret!!!
#client.send(key_2)
public_key2, _ = udp_client.recvfrom(2048)
#public_key2 = load_der_public_key(public_key2)
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

