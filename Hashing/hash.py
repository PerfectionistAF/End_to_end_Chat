import hashlib


def hash_data(data):
	"""
Hashes the provided data with hashlib using the specified hash function.

Args:
    data: The data to be hashed (str, bytes, etc.).
      
Returns:
    The SHA256 digest as a hexadecimal string.
	"""

	# Insure that the data is a string or byte array
	if isinstance(data, str):
		data = data.encode("utf-8")

	# Use SHA256 Algorithm 
	hash = hashlib.sha256()

	# Set data to be hashed
	hash.update(data)

	# Return hexadecimal digest as a string
	return hash.hexdigest()


def verify_hash(hashed_data, data):
    """
Checks the hash value if it matches the data.
NOTE: Uses environment variables to load cryptographic key

Args:
    hashed_value: String containing the hexadigest to be compared
    data: The data to be checked (str, bytes, etc.).
      
Returns:
    Wether the hashed_value matches the data
  	"""
    return (hashed_data == hash_data(data))


print(hash_data("MyPassword1"))
print(verify_hash("ac5b208b4d35ec79fa7c14b7a31f9c80392cdab2bc58bc5b79bcfe64b044d899", "MyPassword1"))
