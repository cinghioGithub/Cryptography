from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64

password = b'password'
salt = get_random_bytes(16)  #almeno 16 byte

key = scrypt(password, salt, 32, N=2**20, r=8, p=1)

print(key)
print(base64.b64encode(key).decode())