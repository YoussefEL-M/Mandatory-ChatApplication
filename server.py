import socket
from cryptography.exceptions import InvalidTag
from utils import *

HOST = '127.0.0.1'
PORT = 10001

# Opsætning af Socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

conn, addr = server_socket.accept()
print('Connected to ', addr)

# Generere salt
salt = os.urandom(16)
conn.sendall(salt)

key_2 = conn.recv(97)
key = derive_key(key_2, salt)
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

