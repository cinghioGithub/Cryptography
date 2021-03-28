from Crypto.Hash import SHA3_256
import base64

#data = b'message for computing the hash'

digest = SHA3_256.new()

with open('./6.SHA256.py', "rb") as finput:
    digest.update(finput.read())

print(digest.hexdigest())
print(digest.hexdigest().__len__()*4)