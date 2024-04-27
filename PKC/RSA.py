import threading
import socket
import rsa

public_key, private_key = rsa.newkeys(1024)
partner_public_key = None

choice = input("Enter (1) to become a host. Enter (2) or to connect to existing host: ")

if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("192.168.220.1", 9999))
    server.listen()
    client, _ = server.accept()

    # Send public key
    client.send(public_key.save_pkcs1("PEM"))
    # Receive partner's public key
    partner_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))
elif choice == "2":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("192.168.220.1", 9999))

    # Receive partner's public key
    partner_public_key = rsa.PublicKey.load_pkcs1(client.recv(1024))
    # Send public key
    client.send(public_key.save_pkcs1("PEM"))
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
