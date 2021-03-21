from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import base64

key = get_random_bytes(32)
nonce = get_random_bytes(12)

cipher = ChaCha20.new(key=key, nonce=nonce)

plaintext = b'this is a message to encrypt'

ciphertext = cipher.encrypt(plaintext)

print(ciphertext)

print(cipher.nonce)

nonceb64 = base64.b64encode(nonce)
#nonceb64 = base64.b64encode(cipher.nonce)
ciphertextb64 = base64.b64encode(ciphertext)

#print(nonceb64)
print(plaintext)
#print('Plain text = ' + base64.b64encode(plaintext).decode())
print('Nonce = ' + nonceb64.decode())               #il .decode() serve per poter stampare la sequenza di byte, come una stringa
print('Ciphertext = ' + ciphertextb64.decode())

#==========================================

cipher_dec = ChaCha20.new(key=key, nonce=base64.b64decode(nonceb64))
text_dec = cipher_dec.decrypt(base64.b64decode(ciphertextb64))

print(text_dec)