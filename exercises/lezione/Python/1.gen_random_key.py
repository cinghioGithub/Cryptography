from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

random = get_random_bytes(16)
print(random)
print(type(random))

print(b64encode(random))