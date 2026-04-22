import socket
from cryptography.exceptions import InvalidTag
from utils import *

key_1, key_2 = generate_keys()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 10001))

salt = client.recv(16)

client.send(key_2)
key = derive_key(key_1, salt)

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

