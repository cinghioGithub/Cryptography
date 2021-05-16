from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

N = 1024

#generate key pair
keypair = RSA.generate(N)
#print(keypair.e)
#print(keypair.d)
#print(keypair.n)
#print(keypair.p)
#print(keypair.q)

#export to file
export_key_material = keypair.export_key(format='PEM', pkcs=8,passphrase='mypassphraseforrsa')   #pkcs=1 just for RSA, pcks=8 for every asymmetric protocol

f = open("rsa_key.pem", "wb")
f.write(export_key_material)
f.close

#simulate import
#fread = open("rsa_key.pem", 'r')
#keypair_file = RSA.import_key(fread.read(), passphrase='mypassphraseforrsa')
#print(keypair_file.e)
#print(keypair_file.d)
#print(keypair_file.n)
#print(keypair_file.p)
#print(keypair_file.q)

public_key = keypair.public_key()

####################
# encrypt data = confidentiality = OAEP
message = b'This is another secret message'
rsa_enc = PKCS1_OAEP.new(public_key)
msg_enc = rsa_enc.encrypt(message)
print(msg_enc)

#decrypt
rsa_dec = PKCS1_OAEP.new(keypair)  #passing keypair, is like passing private key
msg_dec = rsa_dec.decrypt(msg_enc)
print(msg_dec.decode())

###############################3
# digital signatures = authc+int = PSS
sig_gen = pss.new(keypair)
hash_gen = SHA256.new(message)
signature = sig_gen.sign(hash_gen)
print(signature)

#############33
# we have the public key
# we have the signature
# we have the message
hash_verifier = SHA256.new(message)
sig_vrfy = pss.new(public_key)

try:
    sig_vrfy.verify(hash_verifier, signature)
    print("OK")
except (ValueError,TypeError):
    print('Wrong signature!')

#manipulated
sig2 = bytearray(signature)
sig2[0] = 1

hash_verifier2 = SHA256.new(message)
sig_verifier = pss.new(public_key)

try:
    sig_verifier.verify(hash_verifier2,sig2)
    print("Signature OK")
except (ValueError,TypeError):
    print("Signature verification failure")