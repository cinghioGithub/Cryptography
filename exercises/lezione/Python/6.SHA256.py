from Crypto.Hash import SHA256
import base64

data = b'part of data I can pass at initialization of digest object'
digest = SHA256.new(data=data)

digest.update(data=b'first part of the data')
digest.update(data=b'second part of data')

print(base64.b64encode(digest.digest()).decode())
print(digest.hexdigest().__len__()*4)