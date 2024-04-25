from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import DES
from datetime import datetime
##experiment without professional method
salt = get_random_bytes(32) 
password = "mypassword"  ##user can set password
#pass = input("Set your password:  ")
#print(salt)

key = PBKDF2(password, salt, dkLen=8)

message = input("YOU: ")
cipher = DES.new(key[0:8], DES.MODE_OFB)

ciphertext = cipher.encrypt(bytes(message, 'utf-8'))
print("Ciphertext: ", ciphertext)
#export to aes_encrypted_test.bin ##to mimic history and backup
with open('des_encrypted_test.bin', 'wb') as f:
    f.write(cipher.iv)
    f.write(ciphertext)
    print('\nTaken at: ', datetime.now(), '\n')

#time to decrypt
with open('des_encrypted_test.bin', 'rb') as f:
    iv = f.read(8)
    decrypt_data = f.read()
    

cipher = DES.new(key, DES.MODE_OFB, iv = iv)
plaintext = cipher.decrypt(decrypt_data)
print("Plaintext: ", plaintext)

#export key and use on multiple files
#for testing purposes
with open('des_key.bin', 'wb') as f:
    f.write(key)

with open('des_salt.bin', 'wb') as f:
    f.write(salt)
    


