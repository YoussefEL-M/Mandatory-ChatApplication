import os
import hashlib
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import utils
import threading

HOST = '127.0.0.1'
PORT = 10001



