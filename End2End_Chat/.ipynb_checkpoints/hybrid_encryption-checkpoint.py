from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from Crypto.Random import get_random_bytes

def generate_rsa_key_pair():
    ##public 
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_symmetric_key(sym_key, rsa_public_key):
    """
    Encrypt symmetric key using RSA public key
    """
    encrypted_sym_key = rsa_public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_sym_key

def decrypt_symmetric_key(encrypted_sym_key, rsa_private_key):
    """
    Decrypt symmetric key using RSA private key
    """
    sym_key = rsa_private_key.decrypt(
        encrypted_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return sym_key

def encrypt_message(message, sym_key):
    """
    Encrypt message using Fernet symmetric key
    """
    f = Fernet(sym_key)
    encrypted_message = f.encrypt(message)
    return encrypted_message

def decrypt_message(encrypted_message, sym_key):
    """
    Decrypt message using Fernet symmetric key
    """
    f = Fernet(sym_key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message

# Generate RSA key pair (do this only once)
private_key, public_key = generate_rsa_key_pair()

# Generate a random symmetric key for AES
sym_key = get_random_bytes(32)  # AES-256

# Encrypt the symmetric key using RSA public key
encrypted_sym_key = encrypt_symmetric_key(sym_key, public_key)

# Encrypt message using Fernet symmetric key
message = b"Hello, this is a secret message."
encrypted_message = encrypt_message(message, sym_key)

# Decrypt the symmetric key using RSA private key
decrypted_sym_key = decrypt_symmetric_key(encrypted_sym_key, private_key)

# Decrypt the message using the decrypted symmetric key
decrypted_message = decrypt_message(encrypted_message, decrypted_sym_key)

print("Original message:", message)
print("Decrypted message:", decrypted_message)
