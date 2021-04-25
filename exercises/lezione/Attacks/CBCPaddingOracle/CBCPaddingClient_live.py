import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *

from mysecret import HOST, PORT
from mysecret import cbc_oracle_iv as iv
from mysecret import cbc_oracle_ciphertext as ciphertext


from Crypto.Cipher import AES



#clean run
server = remote(HOST,PORT)
server.send(iv)
server.send(ciphertext)
response = server.recv(1024)
print(response)
server.close()

########################################
# test after flipping a bit
server = remote(HOST,PORT)
server.send(iv)

c2 = bytearray(ciphertext)

c2[len(c2)-1] = 0
print(c2)

server.send(c2)
response = server.recv(1024)
print(response)
server.close()



#################################3
# guess the size of the block: 64 old ciphers 128 modern ciphers
N = len(ciphertext) // AES.block_size #number of blocks in my ciphertext

last_block = ciphertext[AES.block_size*(N-1):]
original_cipher_block = ciphertext[AES.block_size*(N-2):AES.block_size*(N-1)]
block_to_modify = bytearray(ciphertext[AES.block_size*(N-2):AES.block_size*(N-1)])
initial_part = ciphertext[:AES.block_size*(N-2)]

print(last_block)
print(block_to_modify)
print(initial_part)
print(ciphertext)



# iterate on the last byte of the last block
block_modified = bytearray(16)
p_prime = bytearray(16)
p = bytearray(N*16)

#byte_index = 15 #last byte of the block
c_15 = block_to_modify[15] # original value of the last byte of block n-1

for block in range(N,1,-1):

    # if block == N-1:
    #     print(debug)

    last_block = ciphertext[AES.block_size*(block-1):AES.block_size*(block)]
    block_to_modify = bytearray(ciphertext[AES.block_size*(block-2):AES.block_size*(block-1)])
    original_cipher_block = ciphertext[AES.block_size*(block-2):AES.block_size*(block-1)]
    initial_part = ciphertext[:AES.block_size*(block-2)]
    i = 1
    for byte_index in range(15,-1,-1):   #this cycle if for every byte in a block
        #print(byte_index)
        if i!=1:
            for j in range(15,15-(i-1),-1):
                block_to_modify[j] = p_prime[j] ^ i

        for c_prime15 in range(256):
            #preparing the modified block

            if c_prime15 == c_15: #this is not general: original message has padding = \x01 needs additional checks
                continue

            block_to_modify[byte_index] = c_prime15
            c_to_send = initial_part+block_to_modify+last_block

            server = remote(HOST,PORT)
            server.send(iv)
            server.send(c_to_send)
            response = server.recv(1024)
            #print(response)
            server.close()

            if response == b'OK':
                #print(response)
                #print("Found ",end=' ')

                p_prime[byte_index] = c_prime15 ^ i
                p[(block*16-1)-(15-byte_index)] = original_cipher_block[byte_index] ^ p_prime[byte_index]

                # print(c_prime15)
                # print(p_prime[byte_index])
                # print(p[(block*16-1)-(15-byte_index)])
                # print(chr(p[((block*16-1)-(15-byte_index))]))
            
        i=i+1

#for first block
last_block = ciphertext[:AES.block_size]
block_to_modify = bytearray(iv)
original_cipher_block = iv
block = 1
i=1
for byte_index in range(15,-1,-1):   #this cycle if for every byte in a block
        #print(byte_index)
        if i!=1:
            for j in range(15,15-(i-1),-1):
                block_to_modify[j] = p_prime[j] ^ i

        for c_prime15 in range(256):
            #preparing the modified block

            if c_prime15 == c_15: #this is not general: original message has padding = \x01 needs additional checks
                continue

            block_to_modify[byte_index] = c_prime15
            c_to_send = last_block

            server = remote(HOST,PORT)
            server.send(block_to_modify)
            server.send(c_to_send)
            response = server.recv(1024)
            #print(response)
            server.close()

            if response == b'OK':
                #print(response)
                #print("Found ",end=' ')

                p_prime[byte_index] = c_prime15 ^ i
                p[(block*16-1)-(15-byte_index)] = original_cipher_block[byte_index] ^ p_prime[byte_index]

                # print(c_prime15)
                # print(p_prime[byte_index])
                # print(p[(block*16-1)-(15-byte_index)])
                # print(chr(p[((block*16-1)-(15-byte_index))]))
            
        i=i+1

print(p)
print(byte_index)



############################################
# print("Second last byte")
# c_second15 = p_prime15 ^ 2
# block_to_modify[byte_index] = c_second15

# byte_index = 14 # 14

# c14 = block_to_modify[byte_index]

# for c_prime14 in range(256):
#     block_to_modify[byte_index] = c_prime14

#     c_to_send = initial_part + block_to_modify + last_block

#     server = remote(HOST, PORT)
#     server.send(iv)
#     server.send(c_to_send)
#     response = server.recv(1024)
#     server.close()

#     if response == b'OK':
#         print(response)
#         print("Found ", end=' ')
#         print(c_prime14)

#         p_prime14 = c_prime14 ^ 2
#         p14 = c14 ^ p_prime14

#         print(p_prime14)
#         print(p14)
#         print(chr(p14))