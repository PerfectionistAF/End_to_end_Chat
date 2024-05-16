###testing and integration

##import components
#import Authentication.auth

##import libraries


##step one sign in / sign up input screen
##check sign in function else, generate exception
##step two welcome from sign in 

#start realtime chat
#user can choose either 
    
import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Generate RSA key pair
key = RSA.generate(2048)

# Create AES cipher
def encrypt_aes(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(data)
    iv = cipher.iv
    return iv + ct_bytes

def decrypt_aes(key, data):
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(data[AES.block_size:])
    return pt.rstrip(bytes('\0'))

# Server
def server_program():
    host = socket.gethostname()
    port = 5000  # initiate port
    server_socket = socket.socket()  # get instance
    server_socket.bind((host, port))  # bind host address and port together
    server_socket.listen(2)

    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    conn.send(key.publickey().export_key())  # send public key

    aes_key = get_random_bytes(16)  # generate AES key
    conn.send(encrypt_aes(key.publickey(), aes_key))  # encrypt AES key with RSA and send

    while True:
        data = conn.recv(1024)
        if not data:
            break
        data = decrypt_aes(aes_key, data)
        print("from connected user: " + str(data))
        data = input(' -> ')
        conn.send(encrypt_aes(aes_key, bytes(data, 'utf-8')))  # send data to the client

    conn.close()  # close the connection

# Client
def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # initiate port

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    rsa_public_key = RSA.import_key(client_socket.recv(2048))  # receive public key
    aes_key_encrypted = client_socket.recv(256)  # receive encrypted AES key
    aes_key = decrypt_aes(key, aes_key_encrypted)  # decrypt AES key

    message = input(" -> ")  # take input
    while message.lower().strip() != 'bye':
        client_socket.send(encrypt_aes(aes_key, bytes(message, 'utf-8')))  # send message
        data = client_socket.recv(1024).decode()  # receive response
        print('Received from server: ' + data)  # show in terminal
        message = input(" -> ")  # again take input

    client_socket.close()  # close the connection

if __name__ == '__main__':
    choice = input("Enter S for server or C for client: ").lower()
    if choice == 's':
        server_program()
    elif choice == 'c':
        client_program()






