# End to end Encrypted Chat 

End to end encryption is a private communication system in which only communicating users can participate. This project employs hybrid encryption using a variety of cryptography techniques in a security suite as well as threading and socket programming on an end-to-end encrypted chat.

## Requirements

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the following:
```bash
pip install socket
pip install threading
pip install pycryptodome
pip install rsa
pip install cryptography
pip install hashlib
```

## Main Modules
### Part One:
**1) Block Cipher:** Start with a password, a salt, and a generated key. A ciphertext is output using those 3. To decrypt this text, the input 
vector is required as well as an unpadding if necessary. This module 
aims to encrypt the messages between clients in an end to end 
encrypted chat.

**2) Public Key Cryptography:** As inferred from the user story: "As a user, I want to use public key cryptosystems to securely share keys with my communication 
partner", the public key cryptosystem module will be used to derive 
and share an encryption key that will be used for symmetric
encryption. This is explained further in the ECC module in this 
document

**3) Hashing:** We can ensure data integrity by sending the data’s hash along with 
the data, the receiver checks if the data is the same as the one 
provided by the sender thus confirming the data integrity.

### Part Two:
**4) User Authentication:** This module targets user identity verification, through password. Firebase Authentication via the pyrebase python library. Firebase Authentication is a service, provided by Google Firebase, that offers several authentication methods and handles user sign-up, user sign-in, and other account management tasks. We implemented the Firebase email and password authentication method.

**5) Key Management:** 


## Integration
Integration was performed through the use of teo main types of architectures:
**1) Hybrid Encryption:** This is a user customizable integration architecture that can apply symmetric, asymmetric and key management procedures. All after verifying user identity. The process occurs at each side separately . Start at each host and client with public key then decrypt with private key  

**2) Key Message Passing:** This is also a user customizable technique. The user only chooses how they wish to generate the keys, but the sequence of transmission and generation remains hard coded. The host key is used for first encryption before the message is sent. At the client's side, the client private key is used to decrypt that message. The keys are usually not the same, but the message is sent and decrypted correctly.

## Testing



