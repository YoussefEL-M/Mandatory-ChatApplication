import socket
from utils import *

HOST = '127.0.0.1'
PORT = 10001

password = input("Enter the password: ")

# Opsætning af Socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)

conn, addr = server_socket.accept()
print('Connected to ', addr)

# Generere salt
salt = os.urandom(16)
conn.sendall(salt)

key = derive_key(password, salt)
print("Key derived! Start chatting, write 'exit' to quit")

while True:
    message = input("You: ")
    if message.lower() == "exit":
        break
    conn.sendall(encrypt(key, message))

    data = conn.recv(1024)
    if not data:
        break
    print("Server: " + decrypt(key, data))
conn.close()
server_socket.close()

