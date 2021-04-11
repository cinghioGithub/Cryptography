from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Random.random import randint

#Short-Key Cipher: encryption and decryption functions
#keys are integers: 1byte:
def shortkey8_enc(key, message, iv):
    cipher = AES.new(key.to_bytes(16,byteorder ='big'),AES.MODE_CBC, iv)
    return cipher.encrypt(pad(message,AES.block_size))

def shortkey8_dec(key, message, iv): #1byte key decryption
    cipher = AES.new(key.to_bytes(16,byteorder ='big'),AES.MODE_CBC, iv)
    return cipher.decrypt(message)

#double encryption
def double8_enc(key1, key2, message, iv):
    # print(key1.to_bytes(16,byteorder ='big'))
    # print(key2.to_bytes(16, byteorder='big'))
    cipher1 = AES.new(key1.to_bytes(16,byteorder ='big'),AES.MODE_CBC, iv)
    cipher2 = AES.new(key2.to_bytes(16,byteorder ='big'),AES.MODE_CBC, iv)
    return cipher2.encrypt(cipher1.encrypt(pad(message,AES.block_size)))

    