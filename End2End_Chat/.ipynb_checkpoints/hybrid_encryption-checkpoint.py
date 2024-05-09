from Crypto.Cipher import AES, PKCS1_OAEP, DES
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes

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
    padded_message = message + (block_size - len(message) % block_size) * b'\0'
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
    return decrypted_message.rstrip(b'\0')

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


##user choice:
choice = input("Enter (1) for RSA + AES | (2) for ECC + AES | (3) for RSA + DES | (4) for ECC + DES :")

if (choice == "1"):
    private_key, public_key = generate_rsa_key_pair()
    sym_key = get_random_bytes(16)  # AES-128
    encrypted_sym_key = rsa_encrypt_symmetric_key(sym_key, public_key)

    #user enters message to be encrypted
    message = input("YOU:")
    message = message.encode('utf-8')
    nonce, ciphertext, tag = aes_encrypt_message(message, sym_key)
    #now we decrypt
    decrypted_sym_key = rsa_decrypt_symmetric_key(encrypted_sym_key, private_key)
    #Decrypt the message using the decrypted symmetric key
    decrypted_message = aes_decrypt_message(nonce, ciphertext, tag, decrypted_sym_key)

    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message)
#############################RSA + AES############################################################################################
elif(choice == "2"):
    private_key, public_key = generate_ecc_key_pair()
    sym_key = get_random_bytes(16)  # AES-128
    encrypted_sym_key = ecc_encrypt_symmetric_key(sym_key, public_key)
    message = input("YOU:")
    message = message.encode('utf-8')
    nonce, ciphertext, tag = aes_encrypt_message(message, sym_key)
    #now we decrypt
    decrypted_sym_key = ecc_decrypt_symmetric_key(encrypted_sym_key, private_key)
    #Decrypt the message using the decrypted symmetric key
    decrypted_message = aes_decrypt_message(nonce, ciphertext, tag, decrypted_sym_key)

    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message)
#############################ECC + AES############################################################################################
elif(choice == "3"):
    private_key, public_key = generate_rsa_key_pair()
    sym_key = get_random_bytes(16)  # AES-128
    encrypted_sym_key = rsa_encrypt_symmetric_key(sym_key, public_key)
    #user enters message to be encrypted
    message = input("YOU:")
    message = message.encode('utf-8')
    encrypted_message = encrypt_message(message, sym_key)
    decrypted_sym_key = rsa_decrypt_symmetric_key(encrypted_sym_key, private_key)
    decrypted_message = des_decrypt_message(encrypted_message, decrypted_sym_key)
    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message)
#############################RSA + DES############################################################################################
elif(choice == "4"):
    private_key, public_key = generate_ecc_key_pair()
    sym_key = get_random_bytes(16)  # AES-128
    encrypted_sym_key = ecc_encrypt_symmetric_key(sym_key, public_key)
    #user enters message to be encrypted
    message = input("YOU:")
    message = message.encode('utf-8')
    encrypted_message = encrypt_message(message, sym_key)
    decrypted_sym_key = ecc_decrypt_symmetric_key(encrypted_sym_key, private_key)
    decrypted_message = des_decrypt_message(encrypted_message, decrypted_sym_key)
    print("Original message:", message)
    print("Encrypted message:", ciphertext)
    print("Decrypted message:", decrypted_message)
#############################ECC + DES############################################################################################
else:
    print("Invalid choice or timeout")