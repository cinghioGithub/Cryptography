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


if __name__ == '__main__':

    MAXKEY = 2**16 - 1

    #generate two 1-byte random key
    k1 = randint(0, MAXKEY)
    k2 = randint(0, MAXKEY)
    print(k1)
    print(k2)

    #generate a random IV
    iv = get_random_bytes(AES.block_size)

    plaintext = b'This message permits to try the meet in the middle attack'
    #double encrypt the message
    ciphertext = double8_enc(k1, k2, plaintext, iv)
    print(ciphertext)

    #create a dictionary to store the pair key1,ciphertext or key2,ciphertext
    intermediatedict = dict()

    #2^8 
    for i in range(MAXKEY):
        intermediate = shortkey8_enc(i, plaintext, iv)
        intermediatedict[intermediate] = i

    for i in range(MAXKEY):
        intermediate = shortkey8_dec(i, ciphertext, iv)
        if intermediate in intermediatedict:
            print("k1:" + str(intermediatedict[intermediate])+ " k2:" + str(i))