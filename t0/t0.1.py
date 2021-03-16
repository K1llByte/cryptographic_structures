from threading import Thread
from queue import Queue
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

def encrypt(message,key,metadata):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()
    encryptor.authenticate_additional_data(metadata)
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return (iv,ciphertext,encryptor.tag)

def decrypt(iv,cipher,key,tag,metadata):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    decryptor.authenticate_additional_data(metadata)
    return decryptor.update(cipher) + decryptor.finalize()

# Emitter thread function
# def emitter(queue):
#     global key
#     msg = b"Hello World!"
#     #print("Message len:",len(msg))
#     iv_ct_tag = encrypt(msg,key,b"METADATA")
#     queue.put(iv_ct_tag)
#     print("[Emitter] Sent > {}".format(iv_ct_tag[1]))

# # Receiver thread function
# def receiver(queue):
#     global key

#     iv,ct,tag = queue.get()
#     print("[Receiver] Received > {}".format(ct))
#     msg = decrypt(iv,ct,key,tag,b"METADATA")
#     print("[Receiver] Decrypted > {}".format(msg))


pwd = b"ola mundo cruel"#bytes(input("Shared Password > "),"utf-8")

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16,
    salt=b"\x00"*16,
    iterations=100000
)
key = kdf.derive(pwd)

# q = Queue(5)
    
# # Create emitter and receiver threads
# e = Thread(target=emitter,args=(q,))
# r = Thread(target=receiver,args=(q,))
    
# # Start both threads
# e.start()
# r.start()

# # Wait for them to finish to exit program
# e.join()
# r.join()
# print("[INFO] > Finished program execution")

msg = b'olaolaol'
iv,ct,tag = encrypt(msg,key,b"METADATA")
msg = decrypt(iv,ct,key,tag,b"METADATA")
