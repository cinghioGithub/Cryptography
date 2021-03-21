from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

key = get_random_bytes(32) #AES256

cipher = AES.new(key, AES.MODE_CBC)
IV = cipher.iv

plaintext = b"Messaggio da cifrare con AES_256_CBC"
 
padded_plain = pad(plaintext, AES.block_size)   #aggiunta del padding al testo in chiaro
print(padded_plain)

cipher_text = cipher.encrypt(padded_plain)
print(cipher_text)

#=============================================

cipher_dec = AES.new(key, AES.MODE_CBC, IV)

dec_text = unpad(cipher_dec.decrypt(cipher_text), AES.block_size)
print(dec_text)