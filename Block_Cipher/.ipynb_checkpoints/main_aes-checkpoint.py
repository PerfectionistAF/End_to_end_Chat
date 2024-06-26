from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

#salt = get_random_bytes(32)  ##at first generate salt then get your key, export salt and password to use for the same cipher generation
salt = bytes('P.\xb8g\xdf\xdc\x87\xec\x9f\x84c\x8at\xb3T\xfc\xeb\xb7\xc5gI\xcc\xdd4\xaa\xa1\x14o\xe1Sq\x9f')
password = "mypassword"  ##user can set password
#pass = input("Set your password:  ")
#print(salt)

key = PBKDF2(password, salt, dkLen=32)

message = input("YOU: ")
cipher = AES.new(key, AES.MODE_CBC)

ciphertext = cipher.encrypt(pad(bytes(message, 'utf-8'), AES.block_size))
print("Ciphertext: ", ciphertext)
#export to aes_encrypted_test.bin ##to mimic history and backup
file = open('aes_encrypted_test.bin', 'wb')
file.write(cipher.iv)
file.write(ciphertext)
print('\nTaken at: ', datetime.now(), '\n')

##################################################################################BUG IN PYTHON
#with open('aes_encrypted_test.bin', 'wb') as file:
#    file.write(cipher.iv)
#    file.write(ciphertext)
#    print('\nTaken at: ', datetime.now(), '\n')
##################################################################################BUG IN PYTHON

#time to decrypt
file = open('aes_encrypted_test.bin', 'rb')
iv = file.read(16)
decrypt_data = file.read()

##################################################################################BUG IN PYTHON
#with open('aes_encrypted_test.bin', 'rb') as f:
#    iv = f.read(16)
#    decrypt_data = f.read()
##################################################################################BUG IN PYTHON    

cipher = AES.new(key, AES.MODE_CBC, iv = iv)
plaintext = unpad(cipher.decrypt(decrypt_data), AES.block_size)
print("Plaintext: ", plaintext)

#export key and use on multiple files
#for testing purposes
file = open('aes_key.bin', 'wb')
file.write(key)

##################################################################################BUG IN PYTHON
#with open('aes_key.bin', 'wb') as f:
#    f.write(key)
##################################################################################BUG IN PYTHON

file = open('aes_salt.bin', 'wb')
file.write(salt)

##################################################################################BUG IN PYTHON
#with open('aes_salt.bin', 'wb') as f:
#    f.write(salt)
##################################################################################BUG IN PYTHON    

