import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from math import ceil
from Crypto.Cipher import AES

from mysecrets import ecb_oracle_key,HOST,PORT



BLOCK_SIZE = AES.block_size
BLOCK_SIZE_HEX = 2*BLOCK_SIZE


server = remote(HOST, PORT)

# stole from the server code...
# message = "This is what I received: " + msg + " -- END OF MESSAGE"
start_str = "This is what I received: "
# print(len(start_str))
pad_len = ceil(len(start_str)/BLOCK_SIZE)*BLOCK_SIZE-len(start_str)

msg = "A"*(16*9+pad_len) #2 * AES.block_size + oad_len
print("Sending: "+msg)
server.send(msg)


ciphertext = server.recv(1024)
ciphertext_hex = ciphertext.hex()
print(ciphertext_hex)

server.close()

print("ciphertext")
for i in range(0,int(len(ciphertext_hex)//BLOCK_SIZE_HEX)):
    print(ciphertext_hex[i*BLOCK_SIZE_HEX:(i+1)*BLOCK_SIZE_HEX])

ecb = 0

if(ciphertext[9*BLOCK_SIZE:10*BLOCK_SIZE] == ciphertext[4*BLOCK_SIZE:5*BLOCK_SIZE]):
    ecb = 1

if ecb == 1:
    print("ECB")
else:
    print("CBC")
