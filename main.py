#end to end encrypted chat example with rsa
#end to end encryption with aes
import socket 
import threading
#import rsa ##uncomment for encrypted end to end chat
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

#host vs client ##tcp packets 
#public and private key for a certain amount of time
#public_key, private_key = rsa.newkeys(1024) #generate keys ##uncomment for encrypted end to end chat
#public_key_partner = None  #none by default ##uncomment for encrypted end to end chat

choice = input("Do you want to host(1) or do you want to connect(2): ")
#get hostname and ip address for later bindings
hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)
if choice == "1" :
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, 8876))  ##port number 8876  
    #command to check your ports:netstat -ano|findstr 9999   OR   netstat -ano  
    server.listen()
    print("server is listening....")

    client, _ = server.accept() #accept server connection to you ##once you accept a connection, send the public key
    #client.send(public_key.save_pkcs1('PEM')) ##uncomment for encrypted end to end chat
    #public_key_partner = rsa.PublicKey.load_pkcs1(client.recv(1024)) ##uncomment for encrypted end to end chat
elif choice == "2": ##we need to know the public keys of each other ##uncomment for encrypted end to end chat
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((IP, 8876))
    print("client is connecting....")
    #public_key_partner = rsa.PublicKey.load_pkcs1(client.recv(1024)) ##uncomment for encrypted end to end chat
    #client.send(public_key.save_pkcs1('PEM')) ##uncomment for encrypted end to end chat
else:
    exit()


def AES_encrypt(message):
    #salt = get_random_bytes(32) 
    salt = bytes('P.\xb8g\xdf\xdc\x87\xec\x9f\x84c\x8at\xb3T\xfc\xeb\xb7\xc5gI\xcc\xdd4\xaa\xa1\x14o\xe1Sq\x9f')
    password = "mypassword"
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return ciphertext, key, cipher.iv


def AES_decrypt(message, key, iv):
    iv = iv
    decrypt_data = message
    cipher = AES.new(key, AES.MODE_CBC, iv = iv)
    plaintext = unpad(cipher.decrypt(decrypt_data), AES.block_size)
    return plaintext

def sending_messages(c):  #sending messages function
    while True :
        message = input("")
        #encode message beofre packets sent
        #now you encrypt 
        c.send(message.encode())
        #c.send(rsa.encrypt(message.encode(), public_key_partner)) ##uncomment for encrypted end to end chat
        print("YOU: " + message)
        print("\nENCRYPTED: ", AES_encrypt(bytes(message, 'utf-8')))

def receiving_messages(c):  #receiving messages function
    while True :
        #decode message after packets sent ###no decoding once encrypted 
        print("PARTNER: " + c.recv(1024).decode())  
        #now you decrypt
        #print("PARTNER: " + rsa.decrypt(c.recv(1024), private_key).decode()) ##uncomment for encrypted end to end chat


threading.Thread(target = sending_messages, args = (client, )).start()
threading.Thread(target = receiving_messages, args = (client, )).start()
