from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
import base64

plaintext1 = b'First part of the message'
plaintext2 = b'Secondo part of the message'

key = get_random_bytes(16)
#nonce = get_random_bytes(Salsa20.block_size)

cipher = Salsa20.new(key)

print(base64.b64encode(key))

#è possibile aggiornare il testo cifrato con nuove parti di testo in chiaro
#la cifratra è incrementale
cipher_text = cipher.encrypt(plaintext1)
cipher_text += cipher.encrypt(plaintext2)

print('Cipher text = ' + base64.b64encode(cipher_text).decode())

#==============================================

cipher_dec = Salsa20.new(key=key, nonce=cipher.nonce)
plaintext = cipher_dec.decrypt(cipher_text)

#print('Plain text decrypted = ' + base64.b64encode(plaintext).decode())
print(plaintext)