from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import threading
import socket
import rsa
import binascii
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import os

# Function to handle RSA key exchange for client
def rsa_client():
    # Receive partner's public key
    partner_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))
    # Send public key
    client.send(public_key.save_pkcs1("PEM"))
    return partner_public_key

# Function to handle RSA key exchange for server
def rsa_server():
    # Send public key
    client.send(public_key.save_pkcs1("PEM"))
    # Receive partner's public key
    return rsa.PublicKey.load_pkcs1(client.recv(1024))

# Function to receive a file
def receive_file(client, filename):
    with open(filename, "wb") as f:
        while True:
            data = client.recv(1024)
            if not data:
                break
            f.write(data)
    print("File received successfully.")

# Function to send a file
def send_file(client, filename):
    with open(filename, "rb") as f:
        while True:
            data = f.read(1024)
            if not data:
                break
            client.send(data)
    print("File sent successfully.")

# Function to send messages (both text and file)
def send_msg(client):
    while True:
        choice = input("Enter (1) to send text message, (2) to send a file: ")
        if choice == "1":
            message = input("Enter message: ")
            client.send(rsa.encrypt(message.encode(), partner_public_key))
            print("You: " + message)
        elif choice == "2":
            filename = input("Enter filename to send: ")
            if not os.path.exists(filename):
                print("File not found.")
                continue
            client.send(b"file")  # Notify receiver that file is being sent
            send_file(client, filename)
        else:
            print("Invalid choice.")

# Function to receive messages (both text and file)
def receive_msg(client):
    while True:
        data = client.recv(1024)
        if data == b"file":
            filename = input("Enter filename to save: ")
            receive_file(client, filename)
        else:
            message = rsa.decrypt(data, private_key).decode()
            print("Partner: " + message)

# Initialize RSA keys
public_key, private_key = rsa.newkeys(1024)
partner_public_key = None

# Get user input for server or client mode
choice = input("Enter (1) to become a host. Enter (2) to connect to an existing host: ")
hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)

# Server mode
if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, 9999))
    server.listen()
    client, _ = server.accept()
    option = client.recv(1024)
    if option.decode() == "1":
        print("RSA + AES")
        public_key, private_key = rsa.newkeys(1024)
        client.send(public_key.save_pkcs1())
        encrypted_symmetric_key = client.recv(1024)
        symmetric_key = rsa.decrypt(bytes(encrypted_symmetric_key), private_key).decode()
        print("RSA decoded AES symmetric key...")
        print("START RECEIVING MESSAGES NOW...")
        while True:
            encrypted_message = client.recv(1024)
            if not encrypted_message:
                break
            iv = encrypted_message[:16]
            ciphertext = encrypted_message[16:]
            cipher_aes = AES.new(symmetric_key.encode(), AES.MODE_CBC, iv=iv)
            decrypt_plaintext = cipher_aes.decrypt(ciphertext)
            plaintext = binascii.b2a_hex(cipher_aes.decrypt(decrypt_plaintext)).decode("utf-8").strip()
            print("Partner:", plaintext)
    elif option.decode() == "3":
        print("RSA + DES")
        public_key, private_key = rsa.newkeys(1024)
        client.send(public_key.save_pkcs1())
        encrypted_symmetric_key = client.recv(1024)
        symmetric_key = rsa.decrypt(bytes(encrypted_symmetric_key), private_key).decode()
        print("RSA decoded AES symmetric key...")
        print("START RECEIVING MESSAGES NOW...")
        while True:
            encrypted_message = client.recv(1024)
            if not encrypted_message:
                break
            iv = encrypted_message[:DES.block_size]
            ciphertext = encrypted_message[DES.block_size:]
            cipher_des = DES.new(symmetric_key.encode(), DES.MODE_CBC, iv=iv)
            plaintext = cipher_des.decrypt(ciphertext).decode().strip()
            print("Partner:", plaintext)

# Client mode
elif choice == "2":
    choice2 = input("Enter (1) for RSA + AES | (3) for RSA + DES: ")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((IP, 9999))
    if choice2 == "1":
        client.send('1'.encode())
        partner_public_key = rsa_client()
        print("START SENDING MESSAGES NOW...")
        threading.Thread(target=send_msg, args=(client,)).start()
        threading.Thread(target=receive_msg, args=(client,)).start()
    elif choice2 == "3":
        client.send('3'.encode())
        partner_public_key = rsa_client()
        print("START SENDING MESSAGES NOW...")
        #threading.Thread(target=send_msg, args=(client,)).start()
        #threading.Thread(target=receive_msg, args=(client,)).start()

else:
    print("Invalid input.")
    exit()
