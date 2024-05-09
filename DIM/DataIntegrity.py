
import hashlib
import os
import socket
import time

def hash_data(data):

	if isinstance(data, str):
		data = data.encode("utf-8")

	hash = hashlib.sha256()

	hash.update(data)

	digest = hash.hexdigest()

	# print("Hash: " +  digest)

	return digest


def verify_hash(hashed_data, data):
	return (hashed_data == hash_data(data))


def host_server(IP:str):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((IP, 8876))
	server.listen()
	print("Server is listening....")

	client, _ = server.accept()
	return client, server

def connect_to_host(IP:str):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((IP, 8876))
    print("Client connected!")
    return client


choice = input("Do you want to host(1) or do you want to connect(2): ")

hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)


if choice == "1" :
	
	client, server = host_server(IP)

	# Receive filename
	filename = client.recv(1024).decode()
	# print("File name: " + filename)

	# Receive hash data
	verification_hash = client.recv(1024).decode()
	# print("Recieved Hash: " + verification_hash)


	os.makedirs("./storage", exist_ok=True)
	file_path = os.path.join("./storage", filename)


	if not os.path.exists(file_path):
		with open(file_path, 'x') as file:
			pass

	with open(file_path, 'wb') as file:
		while True:
			data = client.recv(1024)
			if not data:
				break
			file.write(data)

	with open(filename, 'rb') as file:
		data = file.read().decode()

		if verify_hash(verification_hash, data):
			print("File transfer integrity is confirmed")
		else:
			print("WARNING: File transfer integrity is not confirmed")

	print("File received successfully!")
	client.close()
	server.close()

elif choice == "2":

	client = connect_to_host(IP)
	# filename = input("Enter filename to send: ")
	filename = "text.txt"

	

	with open(filename, 'rb') as file:

		data = file.read(1024)


		client.send((filename).encode())

		time.sleep(1)

		verification_hash = hash_data(data.decode())

		# print("Data: "+data.decode())

		time.sleep(1)

		client.send(verification_hash.encode())

		while data:
			client.send(data)
			data = file.read(1024)

		
	
	print("File sent successfully")
	client.close()
else:
    exit()


