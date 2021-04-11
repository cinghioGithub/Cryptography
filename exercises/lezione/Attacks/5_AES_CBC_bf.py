from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

key = get_random_bytes(16)
iv = get_random_bytes(AES.block_size)

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintex = b'prova per bit flipping 123'

print(plaintex[:16])
print(plaintex[16:])

ciphertext = cipher.encrypt(pad(plaintex, AES.block_size))
print(ciphertext)

index = plaintex.index(b'1')
print(index)

new_plain_block = pad(b'ipping 223', AES.block_size)
print(new_plain_block)

cipher_text_array = bytearray(ciphertext)
new_cipher_text = bytearray(AES.block_size)
#mask = bytearray(AES.block_size)
pad_plain_text =pad(plaintex[16:], AES.block_size)
print(pad(plaintex[16:], AES.block_size))
indice = pad_plain_text.index(b'1')
print(indice)

mask = ord(b'1') ^ ord(b'2')
cipher_text_array[indice] ^= mask

cipherdec = AES.new(key, AES.MODE_CBC, iv)
dec = cipherdec.decrypt(cipher_text_array)
print(dec)

