from Crypto.Util.number import getPrime
from math import gcd

N = 1024
# genero p e phi
p1 = getPrime(N)
p2 = getPrime(N)

n = p1*p2
phi = (p1-1)*(p2-1)

#genero parametri pubblici e privati
e = 65537 #oppure 3
if gcd(e, phi) != 1:
    raise ValueError
    exit(-1)

#e*d = 1 mod phi
d = pow(e, -1, phi)  # d = e^(-1) mod phi

#pair
public_key = (e,n)
private_key = (d,n)

#encrypt a message
msg = b'this is a message to encrypt'
#devo avere il messaggio sotto forma di intero
int_msg = int.from_bytes(msg, byteorder='big')

if int_msg >= n:
    raise ValueError
    exit(-1)

enc = pow(int_msg, e, n)
print(enc)

dec = pow(enc, d, n)
print(dec.to_bytes(N,byteorder='big').decode())