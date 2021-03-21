from Crypto.Random import get_random_bytes
from Crypto.Cipher import Salsa20
import base64
import sys

from mysecret import salsa_key

cipher = Salsa20.new(salsa_key)

foutput = open(sys.argv[2], 'wb')

with open(sys.argv[1], 'rb') as finput:
    plaintext = finput.read(1024)
    cipherText = cipher.encrypt(plaintext)
    foutput.write(cipherText)

foutput.close()
#===========================================

cipher_dec = Salsa20.new(key=salsa_key, nonce=cipher.nonce)

with open(sys.argv[2], 'rb') as dec_input:
    cipherText = dec_input.read(1024)
    plaintext = cipher_dec.decrypt(cipherText)

print(plaintext)