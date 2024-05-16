from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import socket
import rsa
import binascii

public_key, private_key = rsa.newkeys(1024)
partner_public_key = None

choice = input("Enter (1) to become a host. Enter (2) to connect to an existing host: ")
hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)  ## FROM BOB TO ALICE  ## BOB IS THE HOST ## ALICE IS THE CLIENT

if choice == "1":  #####server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, 9999))
    server.listen()
    client, _ = server.accept()
    option = client.recv(1024)
    if option.decode() == "1":
        print("RSA + DES")
        public_key, private_key = rsa.newkeys(1024)
        print("Public key to connections:", public_key)
        # Send public key
        client.send(public_key.save_pkcs1())
        # Receive encoded Symmetric Key and decrypt it using private key
        encrypted_symmetric_key = client.recv(1024)
        symmetric_key = rsa.decrypt(encrypted_symmetric_key, private_key).decode()
        print("RSA decoded DES symmetric key:", symmetric_key)
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
    elif option.decode() == "2":
        print("ECC + DES")
        private_key = generate_eth_key()
        private_key_hex = private_key.to_hex()
        public_key_hex = private_key.public_key.to_hex()
        print(public_key_hex)
        # Send public key
        client.send(public_key_hex.encode())
        # Receive Symmetric Key
        symmetric_key = decrypt(private_key_hex, client.recv(1024)).decode()
    elif option.decode() == "3":
        print("RSA + AES")
        public_key, private_key = rsa.newkeys(1024)
        # Send public key
        client.send(public_key.save_pkcs1())
        # Receive Symmetric Key
        symmetric_key = rsa.decrypt(client.recv(1024), private_key).decode()

elif choice == "2":  #####client
    choice2 = input("Enter (1) for RSA + DES | (2) for ECC + DES | (3) for RSA + AES | (4) for ECC + AES:")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((IP, 9999))
    if choice2 == "1":
        client.send('1'.encode())
        # Receive partner's public key
        partner_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))
        print("Public key received for encryption:", partner_public_key)
        #####################################################
        salt = get_random_bytes(8)  # DES
        password = "12345678"  # DES key size is 8 bytes
        symmetric_key = PBKDF2(password, salt, dkLen=8)
        cipher = DES.new(symmetric_key, DES.MODE_CBC)
        symmetric_key_hex = binascii.b2a_hex(symmetric_key).decode("utf-8").strip()  ## to string
        client.send(rsa.encrypt(symmetric_key_hex.encode(), partner_public_key))
        print("RSA encoded message DES encryption key sent:", symmetric_key_hex)
        print("START SENDING MESSAGES NOW...")
        while True:
            message = input("")
            if message == 'exit':
                break
            print("You:", message)
            # Encrypt using symmetric key
            padded_message = message.ljust(8)  # Padding for DES
            ciphertext = cipher.encrypt(padded_message.encode())
            iv = cipher.iv
            encrypted_message = iv + ciphertext
            client.send(encrypted_message)
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
