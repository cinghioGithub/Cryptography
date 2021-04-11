from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

plaintext = b'This message is used to do a flip bit 123456 attack'

key = get_random_bytes(32)
cipher = ChaCha20.new(key=key)
ciphertext = cipher.encrypt(plaintext)
print(ciphertext)

#attacker side
index = plaintext.index(b'1')   #take the index of the byte '1' in the plaintex
print(index)

new_value = b'2'
print(new_value)
print(ord(new_value))   #print the value of the byte '2' -> 50 (character '2')

#one single byte of a string of bytes is interpretaded as an integer
mask = plaintext[index] ^ ord(new_value)   #xor between the new value and the value I want to change in the plaintext
print(plaintext[index].__class__)
print(mask)

cipher_array = bytearray(ciphertext)
cipher_array[index] ^= mask
print(cipher_array)
print("          " + str(ciphertext))

cipher_dec = ChaCha20.new(key=key, nonce=cipher.nonce)
dec = cipher_dec.decrypt(cipher_array)
print(plaintext)
print(dec)