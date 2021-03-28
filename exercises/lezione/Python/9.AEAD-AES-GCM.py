import base64
import json

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)  #AES_128
cipher = AES.new(key, AES.MODE_GCM)

associated_data = b'associated data to not encrypt'
confidential_data = b'data to enrypt and authenticate'

#solo la parte da non cifrare
cipher.update(associated_data)

#effettua la criptazione il calcolo del mac
ciphertext, tag = cipher.encrypt_and_digest(confidential_data)

packed_data = json.dumps({
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "tag": base64.b64encode(tag).decode(),
    "header": base64.b64encode(associated_data).decode(),
    "nonce": base64.b64encode(cipher.nonce).decode()
})

#==============================
#at the reciever

unpacked_data = json.loads(packed_data)

cipher_verification = AES.new(key, AES.MODE_GCM, base64.b64decode(unpacked_data["nonce"].encode()))

cipher_verification.update(base64.b64decode(unpacked_data["header"].encode()))

try:
    cipher_verification.decrypt_and_verify(base64.b64decode(unpacked_data["ciphertext"].encode()), base64.b64decode(unpacked_data["tag"].encode()))
    print("Verification OK")
except:
    print("Verification FAILED")