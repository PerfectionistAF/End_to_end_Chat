from cryptography.fernet import Fernet

def generate_key():
    #generate new key
    key = Fernet.generate_key()
    with open("fernet_key.bin", "wb") as file:
        file.write(key)

def load_key():
    #load key
    #try except block to add exception handle
    try:
        with open("fernet_key.bin", "rb") as file:
            key = file.read()
        return key
    except FileNotFoundError:
        print("Key file not found. Please generate a key first.")
        exit()

def encrypt_message(message, key):
    #now we encrypt
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    #now we decrypt
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message


if __name__ == "__main__":
    generate_key()  #single key generation
    key = load_key() 

    #user enters a message
    message = input("YOU:")
    encrypted_message = encrypt_message(message, key)
    print("ENCRYPTED:", encrypted_message)

    decrypted_message = decrypt_message(encrypted_message, key)
    print("DECRYPTED:", decrypted_message)
