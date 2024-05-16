from Crypto.Cipher import AES, PKCS1_OAEP, DES
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
import threading
import socket

import rsa


def host_server(IP:str):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((IP, 9999))#8876))  ##socket can only be accessed once ##check antp
	server.listen()
	print("Server is listening....")

	client, _ = server.accept()
	return client, server

def connect_to_host(IP:str):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((IP, 9999))#8876))
    print("Client connected!")
    return client

def generate_rsa_key_pair():
    #public and private keys for rsa
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt_symmetric_key(sym_key, rsa_public_key):
    #Encrypt symmetric key using RSA public key
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
    encrypted_sym_key = rsa_cipher.encrypt(sym_key)
    return encrypted_sym_key

def rsa_decrypt_symmetric_key(encrypted_sym_key, rsa_private_key):
    #Decrypt symmetric key using RSA private key
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(rsa_private_key))
    sym_key = rsa_cipher.decrypt(encrypted_sym_key)
    return sym_key

def generate_ecc_key_pair():
    #public and private keys for ecc
    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return private_key, public_key

def ecc_encrypt_symmetric_key(sym_key, ecc_public_key):
    #Encrypt symmetric key using ECC public key
    ecc_key = ECC.import_key(ecc_public_key)
    ciphertext = ecc_key.encrypt(sym_key, None)
    return ciphertext

def ecc_decrypt_symmetric_key(encrypted_sym_key, ecc_private_key):
    #Decrypt symmetric key using ECC private key
    ecc_key = ECC.import_key(ecc_private_key)
    sym_key = ecc_key.decrypt(encrypted_sym_key)
    return sym_key

def des_pad_message(message):
    #Pad message to match DES block size
    block_size = 8
    padded_message = message + (block_size - len(message) % block_size) * bytes('\0')
    return padded_message

def des_encrypt_message(message, sym_key):
    #Encrypt message using DES symmetric key
    cipher = DES.new(sym_key, DES.MODE_ECB)
    encrypted_message = cipher.encrypt(des_pad_message(message))
    return encrypted_message

def des_decrypt_message(encrypted_message, sym_key):
    #Decrypt message using DES symmetric key
    cipher = DES.new(sym_key, DES.MODE_ECB)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.rstrip(bytes('\0'))

def aes_encrypt_message(message, sym_key):
    #Encrypt message using AES symmetric key
    cipher = AES.new(sym_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag

def aes_decrypt_message(nonce, ciphertext, tag, sym_key):
    #Decrypt message using AES symmetric key
    cipher = AES.new(sym_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_message


def send_msg(client):
    while True:
        message = input("")
        client.send(rsa.encrypt(message.encode(), partner_public_key))
        print("You: " + message)


def receive_msg(client):
    while True:
        print("Partner: " + rsa.decrypt(client.recv(1024), private_key).decode())

hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)
choice = input("Do you want to host(1) or do you want to connect(2): ")
if choice == "1" :
    client, server = host_server(IP)
    option = client.recv(1024)
    if option.decode() == "1":
        print("RSA + AES")
        public_key, private_key = rsa.newkeys(1024)

        partner_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))

        client.send(public_key.save_pkcs1("PEM"))

        # threading.Thread(target=send_msg, args=(client,)).start()
        # threading.Thread(target=receive_msg, args=(client,)).start()


    elif option.decode() == "2":
        print("ECC + AES")
    elif option.decode() == "3":
        print("RSA + DES")
    elif option.decode() == "4":
        print("ECC + DES")
    else:
        print("client is an idiot")
    # client.close()
    # server.close()

if choice == "2":
    client = connect_to_host(IP)
    choice = input("Enter (1) for RSA + AES | (2) for ECC + AES | (3) for RSA + DES | (4) for ECC + DES:")
    if (choice == "1"):
        client.send('1'.encode())
        public_key, private_key = rsa.newkeys(1024)
        client.send(public_key.save_pkcs1("PEM"))

        partner_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))

        # threading.Thread(target=send_msg, args=(client,)).start()
        # threading.Thread(target=receive_msg, args=(client,)).start()


        # #user enters message to be encrypted
        # message = input("YOU:")
        # message = message.encode('utf-8')
        # nonce, ciphertext, tag = aes_encrypt_message(message, sym_key)
        # #now we decrypt
        # decrypted_sym_key = rsa_decrypt_symmetric_key(encrypted_sym_key, private_key)
        # #Decrypt the message using the decrypted symmetric key
        # decrypted_message = aes_decrypt_message(nonce, ciphertext, tag, decrypted_sym_key)
    elif (choice == "2"):
        client.send('2'.encode())
    elif (choice == "3"):
        client.send('3'.encode())
    elif (choice == "4"):
        client.send('4'.encode())
    else:
        client.send('nope'.encode())
    client.close()
        # private_key, public_key = generate_rsa_key_pair()
        # sym_key = get_random_bytes(16)  # AES-128
        # encrypted_sym_key = rsa_encrypt_symmetric_key(sym_key, public_key)

        # #user enters message to be encrypted
        # message = input("YOU:")
        # message = message.encode('utf-8')
        # nonce, ciphertext, tag = aes_encrypt_message(message, sym_key)
        # #now we decrypt
        # decrypted_sym_key = rsa_decrypt_symmetric_key(encrypted_sym_key, private_key)
        # #Decrypt the message using the decrypted symmetric key
        # decrypted_message = aes_decrypt_message(nonce, ciphertext, tag, decrypted_sym_key)

        # print("Original message:", message)
        # print("Encrypted message:", ciphertext)
        # print("Decrypted message:", decrypted_message)
    #############################RSA + AES############################################################################################
    # elif(choice == "2"):
    #     private_key, public_key = generate_ecc_key_pair()
    #     sym_key = get_random_bytes(8)  # AES-128
    #     encrypted_sym_key = ecc_encrypt_symmetric_key(sym_key, public_key)
    #     message = input("YOU:")
    #     message = message.encode('utf-8')
    #     nonce, ciphertext, tag = aes_encrypt_message(message, sym_key)
    #     #now we decrypt
    #     decrypted_sym_key = ecc_decrypt_symmetric_key(encrypted_sym_key, private_key)
    #     #Decrypt the message using the decrypted symmetric key
    #     decrypted_message = aes_decrypt_message(nonce, ciphertext, tag, decrypted_sym_key)

    #     print("Original message:", message)
    #     print("Encrypted message:", ciphertext)
    #     print("Decrypted message:", decrypted_message)
    # #############################ECC + AES############################################################################################
    # elif(choice == "3"):
    #     private_key, public_key = generate_rsa_key_pair()
    #     sym_key = get_random_bytes(8)  # AES-128
    #     encrypted_sym_key = rsa_encrypt_symmetric_key(sym_key, public_key)
    #     #user enters message to be encrypted
    #     message = input("YOU:")
    #     message = message.encode('utf-8')
    #     encrypted_message = des_encrypt_message(message, sym_key)
    #     decrypted_sym_key = rsa_decrypt_symmetric_key(encrypted_sym_key, private_key)
    #     decrypted_message = des_decrypt_message(encrypted_message, decrypted_sym_key)
    #     print("Original message:", message)
    #     print("Encrypted message:", encrypted_message)
    #     print("Decrypted message:", decrypted_message)
    # #############################RSA + DES############################################################################################
    # elif(choice == "4"):
    #     private_key, public_key = generate_ecc_key_pair()
    #     sym_key = get_random_bytes(8)  # AES-128
    #     encrypted_sym_key = ecc_encrypt_symmetric_key(sym_key, public_key)
    #     #user enters message to be encrypted
    #     message = input("YOU:")
    #     message = message.encode('utf-8')
    #     encrypted_message = des_encrypt_message(message, sym_key)
    #     decrypted_sym_key = ecc_decrypt_symmetric_key(encrypted_sym_key, private_key)
    #     decrypted_message = des_decrypt_message(encrypted_message, decrypted_sym_key)
    #     print("Original message:", message)
    #     print("Encrypted message:", encrypted_message)
    #     print("Decrypted message:", decrypted_message)
    # #############################ECC + DES############################################################################################
    # else:
    #     print("Invalid choice or timeout")


    # threading.Thread(target = sending_messages, args = (client, )).start()
    # threading.Thread(target = receiving_messages, args = (client, )).start()
##user choice:

