import threading
import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# Generating ECC key pair
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()
public_partner = None

choice = input("Enter (1) to become a host. Enter (2) or to connect to existing host: ")
hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)
if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #server.bind(("192.168.220.1", 9999))
    server.bind((IP, 9999))
    server.listen()
    client, _ = server.accept()

    # Send public key
    client.send(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    # Receive partner's public key
    public_partner = serialization.load_pem_public_key(client.recv(1024), backend=default_backend())

elif choice == "2":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #client.connect(("192.168.220.1", 9999))
    client.connect((IP, 9999))

    # Receive partner's public key
    public_partner = serialization.load_pem_public_key(client.recv(1024), backend=default_backend())
    # Send public key
    client.send(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

else:
    exit()


def derive_shared_key(private_key, public_partner):
    shared_key = private_key.exchange(ec.ECDH(), public_partner)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=bytes('handshake data'),
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

def send_msg(client, derived_key):
    while True:
        message = input("")
        ###
        # Encryption to be done using AES and derived_key after integration with AES module in the coming milestones
        ###
        print("You: " + message)


def receive_msg(client, derived_key):
    while True:
        ###
        # Decryption to be done using AES and derived_key after integration with AES module in the coming milestones
        ###
        print("Partner: " + message)


threading.Thread(target=send_msg, args=(client,)).start()
threading.Thread(target=receive_msg, args=(client,)).start()