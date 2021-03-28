import base64
import json
from Crypto.Hash import HMAC, SHA512
from Crypto.Random import get_random_bytes

key = get_random_bytes(16)   #chiave da 64 bit
message = b'message for computing the hmac'

#inizializzazione dell'oggeto hmac
hmac = HMAC.new(digestmod=SHA512, key=key)
hmac.update(message[:20])   #prendo la prima parte del messggio
hmac.update(message[20:])

print(hmac.hexdigest())
print(hmac.hexdigest().__len__()*4)

#impacchetto i dati dentro un json
mac = base64.b64encode(hmac.digest()).decode()  #ottengo il MAC sotto forma di stringa
#mac = hmac.digest().decode()    #il problema di questa scrittura è che posso avere byte che rappresentano caratteri non stampabili
print(mac)

packed_data = json.dumps({"message": message.decode(), "mac": mac, "algo": "SHA512"})

#==============================
#we are at the reciever
unpacked_data = json.loads(packed_data)

hmac_verifier = HMAC.new(digestmod=SHA512, key=key)
hmac_verifier.update(unpacked_data["message"].encode())

print(hmac_verifier.hexdigest())

try:
    hmac_verifier.verify(base64.b64decode(unpacked_data["mac"].encode()))   #encode() potrebbe essere omesso
    #hmac_verifier.verify(unpacked_data["mac"].encode())
    print('Verification OK!')
except:
    print('Verificatio FAILED!')

byte = bytearray(base64.b64decode(unpacked_data["mac"].encode()))
#print(byte)
print(base64.b64encode(byte).decode())
byte[0] += 1
print(base64.b64encode(byte).decode())   #mac modificato

try:
    hmac_verifier.verify(byte)
    #hmac_verifier.verify(unpacked_data["mac"].encode())
    print('Verification OK!')
except:
    print('Verificatio FAILED!')