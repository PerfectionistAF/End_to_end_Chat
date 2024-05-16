from Crypto.Cipher import AES, PKCS1_OAEP, DES
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import threading
import socket
import rsa
import binascii
from unidecode import unidecode
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt

#import Authentication.auth

def rsa_client():
	# Receive partner's public key
    partner_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))
    # Send public key
    client.send(public_key.save_pkcs1("PEM"))
    return partner_public_key
    
def rsa_server():
    # Send public key
    client.send(public_key.save_pkcs1("PEM"))
    # Receive partner's public key
    return rsa.PublicKey.load_pkcs1(client.recv(1024))

public_key, private_key = rsa.newkeys(1024)
partner_public_key = None

choice = input("Enter (1) to become a host. Enter (2) to connect to existing host: ")
hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)  ##FROM BOB TO ALICE  ##BOB IS THE HOST ##ALICE IS THE CLIENT
if choice == "1":  #####server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, 9999))
    server.listen()
    client, _ = server.accept()
    option = client.recv(1024)
    if option.decode() == "1":
        print("RSA + AES")
        public_key, private_key = rsa.newkeys(1024)
        print("Public key to connections... ")#, public_key)
        # Send public key
        client.send(public_key.save_pkcs1("PEM"))
        # Receive encoded Symmetric Key and decrypt it using private key
        symmetric_key = rsa.decrypt(client.recv(1024), private_key).decode()
        print("RSA decoded aes symmetric key... ")#, symmetric_key)
        print("START RECEIVING MESSAGES NOW...")
        message = client.recv(1024).decode()
        print(message)
        iv = message[0:16]
        decrypt_data = message
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv = iv)
        plaintext = unpad(cipher.decrypt(decrypt_data), AES.block_size)
        print("Partner: " + plaintext.decode())
    elif option.decode() == "2":
        print("ECC + AES")
        private_key = generate_eth_key()
        private_key_hex = private_key.to_hex()
        public_key_hex = private_key.public_key.to_hex()
        print(public_key_hex)
        # Send public key
        client.send(public_key_hex.encode())
        # Receive Symmetric Key
        symmetric_key = decrypt(private_key_hex, client.recv(1024)).decode()
        #print(symmetric_key)
    elif option.decode() == "3":
        print("RSA + DES")
        public_key, private_key = rsa.newkeys(1024)
        # Send public key
        client.send(public_key.save_pkcs1("PEM"))
        # Receive Symmetric Key
        symmetric_key = rsa.decrypt(client.recv(1024), private_key).decode()
    

    
elif choice == "2":  #####client
    choice2 = input("Enter (1) for RSA + AES | (2) for ECC + AES | (3) for RSA + DES | (4) for ECC + DES:")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((IP, 9999))
    if choice2 == "1":
        client.send('1'.encode())
        # Receive partner's public key
        partner_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))
        print("Public key received for encryption... ")#, partner_public_key)
        #####################################################
        salt = get_random_bytes(16)  #AES-128
        #auth.signin.password  #use logged in password to create relationship between confidentiality and authentication
        password = "12345"
        symmetric_key = PBKDF2(password, salt, dkLen=16)
        #print(type(symmetric_key))##bytes
        cipher = AES.new(symmetric_key, AES.MODE_CBC)
        # Send the public key encoded aes symmetric key
        symmetric_key = binascii.b2a_hex(symmetric_key).decode("utf-8").strip()  ##to string
        client.send(rsa.encrypt(symmetric_key.encode(), partner_public_key))
        print("RSA encoded message aes encryption key sent... ")#, rsa.encrypt(symmetric_key.encode(), partner_public_key))
        #client.send(rsa.encrypt("SYMMETRIC KEY".encode(), partner_public_key))
        print("START SENDING MESSAGES NOW...")
        message = input("")
        print("You: " + message)
        #Encrypt using symmetric key
        ciphertext = cipher.encrypt(pad(bytes(message, 'utf-8'), AES.block_size))
        print("Encrypted YOU: ", ciphertext)
    if choice2 == "2":
        client.send('2'.encode())
        # Receive partner's public key
        partner_public_key = client.recv(1024).decode()
        #####################################################
        # Send Symmetric Key
        client.send(encrypt(partner_public_key, "plaintext".encode()))
        
        
        

    
    

else:
    print("Invalid input.")
    exit()

    


def send_msg(client):
    while True:
        message = input("")

        client.send(rsa.encrypt(message.encode(), partner_public_key))
        print("You: " + message)


def receive_msg(client):
    while True:
        print("Partner: " + rsa.decrypt(client.recv(1024), private_key).decode())


threading.Thread(target=send_msg, args=(client,)).start()
threading.Thread(target=receive_msg, args=(client,)).start()