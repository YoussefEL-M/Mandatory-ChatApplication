import socket
from utils import *


password = input("Enter the password: ")


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 10001))

salt = client.recv(16)

key = derive_key(password, salt)

while True:
    data = client.recv(1024)
    if not data:
        break
    print("Client: ", decrypt(key, data))
    message = input("Message: ")
    if message == "exit":
        break

    client.sendall(encrypt(key, message))
client.close()

