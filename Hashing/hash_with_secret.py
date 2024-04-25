from hmac import HMAC
from dotenv import load_dotenv # using python-dotenv package
import os

# Load environment variables from the .env file
load_dotenv()

def hash_data_secretly(data):
    """
Hashes the provided data with HMAC using the specified hash function and secret key.
NOTE: Uses environment variables to load cryptographic key

Args:
    data: The data to be hashed (str, bytes, etc.).
      
Returns:
    The HMAC digest as a hexadecimal string.
  	"""

    # Insure that the data is a string or byte array
    if isinstance(data, str):
        data = data.encode("utf-8")

    key = os.environ["CRYPTO_SECRET_KEY"]

    # Get hash from HMAC using SHA256 algorithm
    hash = HMAC(key.encode("utf-8"), data, "SHA256")

    # Read the hashed value in Hexadecimal
    hashed_data = hash.hexdigest()

    return hashed_data

def verify_secret_hash(hashed_data, data):
    """
Checks the hash value if it matches the data.
NOTE: Uses environment variables to load cryptographic key

Args:
    hashed_value: String containing the hexadigest to be compared
    data: The data to be checked (str, bytes, etc.).
      
Returns:
    Wether the hashed_value matches the data
  	"""
    return (hashed_data == hash_data_secretly(data))

print(hash_data_secretly("MyPassword1"))
print(verify_secret_hash("ac5b208b4d35ec79fa7c14b7a31f9c80392cdab2bc58bc5b79bcfe64b044d899", "MyPassword1"))
