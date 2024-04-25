from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import DES


with open('des_salt.bin', 'rb') as f:
    salt = f.read()

password = "mypassword"  ##user can set their own password
key_check = PBKDF2(password, salt, dkLen=8)

with open('des_key.bin', 'rb') as f:
    key = f.read()

with open('des_encrypted_test.bin', 'rb') as f:
    iv = f.read(8)
    decrypt_data = f.read()

cipher = DES.new(key, DES.MODE_OFB, iv = iv)
plaintext = cipher.decrypt(decrypt_data)

print("Plaintext test from binary files: ", plaintext)
print("\nTEST TRIPLE DES: \n")
#test triple encryption: E, D, E
def DES_encrypt(message):
    salt = get_random_bytes(32) 
    #salt = b'P.\xb8g\xdf\xdc\x87\xec\x9f\x84c\x8at\xb3T\xfc\xeb\xb7\xc5gI\xcc\xdd4\xaa\xa1\x14o\xe1Sq\x9f'
    password = "mypassword"
    key = PBKDF2(password, salt, dkLen=8)
    cipher = DES.new(key[0:8], DES.MODE_OFB)
    ciphertext = cipher.encrypt(message)
    return ciphertext, key, cipher.iv


def DES_decrypt(message, key, iv):
    iv = iv
    decrypt_data = message
    cipher = DES.new(key, DES.MODE_OFB, iv = iv)
    plaintext = cipher.decrypt(decrypt_data)
    return plaintext


message = input("YOU: ")
cipher_0, key_0, iv_0 = DES_encrypt(bytes(message, 'utf-8'))
print('\n')
print('Ciphertext_0: ', cipher_0, '\n')
print('Key_0: ', key_0, '\n')
decipher_0 = DES_decrypt(cipher_0, key_0, iv_0)
print('Plaintext_0: ', decipher_0, '\n')
cipher_1, key_1, iv_1 = DES_encrypt(decipher_0)
print('Ciphertext_1: ', cipher_1, '\n')
print('Key_1: ', key_1, '\n')


