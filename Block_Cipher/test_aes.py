from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
#from datetime import datetime

with open('aes_salt.bin', 'rb') as f:
    salt = f.read()

password = "mypassword"  ##user can set their own password
key_check = PBKDF2(password, salt, dkLen=32)

with open('aes_key.bin', 'rb') as f:
    key = f.read()

with open('aes_encrypted_test.bin', 'rb') as f:
    iv = f.read(16)
    decrypt_data = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv = iv)
plaintext = unpad(cipher.decrypt(decrypt_data), AES.block_size)

print("Plaintext test from binary files: ", plaintext)
print("\nTEST TRIPLE AES: \n")
#test triple encryption: E, D, E
def AES_encrypt(message):
    salt = get_random_bytes(32) 
    #salt = b'P.\xb8g\xdf\xdc\x87\xec\x9f\x84c\x8at\xb3T\xfc\xeb\xb7\xc5gI\xcc\xdd4\xaa\xa1\x14o\xe1Sq\x9f'
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


message = input("YOU: ")
cipher_0, key_0, iv_0 = AES_encrypt(bytes(message, 'utf-8'))
print('\n')
print('Ciphertext_0: ', cipher_0, '\n')
print('Key_0: ', key_0, '\n')
decipher_0 = AES_decrypt(cipher_0, key_0, iv_0)
print('Plaintext_0: ', decipher_0, '\n')
cipher_1, key_1, iv_1 = AES_encrypt(decipher_0)
print('Ciphertext_1: ', cipher_1, '\n')
print('Key_1: ', key_1, '\n')

