# End to end Encrypted Chat 

End to end encryption is a private communication system in which only communicating users can participate. This project employs various cryptography techniques in a security suite as well as threading and socket programming on an end-to-end encrypted chat.

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
**4) User Authentication:** This module targets user identity verification, either through password or certificate.

**5) Key Management:** 


## Integration


## Testing



