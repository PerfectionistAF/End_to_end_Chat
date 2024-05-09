from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
##using aes and rsa
###same as hybrid encryption functions
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_symmetric_key(sym_key, rsa_public_key):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
    encrypted_sym_key = rsa_cipher.encrypt(sym_key)
    return encrypted_sym_key

def decrypt_symmetric_key(encrypted_sym_key, rsa_private_key):
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(rsa_private_key))
    sym_key = rsa_cipher.decrypt(encrypted_sym_key)
    return sym_key

def encrypt_message(message, sym_key):
    cipher = AES.new(sym_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag

def decrypt_message(nonce, ciphertext, tag, sym_key):
    cipher = AES.new(sym_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_message

#Alice
alice_private_key, alice_public_key = generate_rsa_key_pair()
sym_key = get_random_bytes(16)  # AES-128
#Use Alice rsa public key to encrypt sym key
encrypted_sym_key = encrypt_symmetric_key(sym_key, alice_public_key)
#User message example
message = b"Hello. Bob. Please receive this secret message secretly."
#encrypt alice msg with aes
nonce, ciphertext, tag = encrypt_message(message, sym_key)

#Bob
#Use Bob private key to decrypt sym key
decrypted_sym_key = decrypt_symmetric_key(encrypted_sym_key, alice_private_key)

#decrypt alice msg to bob with aes
decrypted_message = decrypt_message(nonce, ciphertext, tag, decrypted_sym_key)

print("Original message:", message)
print("Encrypted message:", ciphertext)
print("Decrypted message:", decrypted_message)