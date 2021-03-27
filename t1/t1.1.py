from threading import Thread
from queue import Queue
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

# Diffie-Hellman
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class Logger:
    def __init__(self,name):
        self.thread_name = name

    def sent(self,msg):
        print("[{}] Sent > {}".format(self.thread_name,msg))

    def received(self,msg):
        print("[{}] Received > {}".format(self.thread_name,msg))

    def log(self,msg):
        print("[{}] > {}".format(self.thread_name,msg))


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
def emitter(channel):
    logger = Logger("Emitter")
    logger.log("Logger initialized")

    # Start Diffie-Hellman Key Exchange

    # Emiter generates some DH parameters and sends to Receiver
    parameters = dh.generate_parameters(generator=2, key_size=1024)
    logger.log("Generated parameters")
    channel.e2r.put(parameters)
    logger.sent("DH parameters")

    # Entities generate both private and public keys
    private_key = parameters.generate_private_key()
    logger.log("Generated private key")
    public_key = private_key.public_key()
    logger.log("Generated public key")
        
    # Send public_key to other peer
    channel.e2r.put(public_key)

    # Receive other peer's public_key
    peer_public_key = channel.r2e.get()

    # Derive shared key
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)

    # End Diffie-Hellman Key Exchange
    
    logger.log(derived_key)

    #msg = b"Hello World!"
    #channel.e2r.put(msg)
    #logger.sent(msg)
    #msg = channel.r2e.get()
    #logger.sent(msg)

# Receiver thread function
def receiver(channel):
    logger = Logger("Receiver")
    logger.log("Logger initialized")

    #### Start Diffie-Hellman Key Exchange ####

    # Get Emitter DH parameters
    parameters = channel.e2r.get()
    logger.received("DH parameters")
    
    private_key = parameters.generate_private_key()
    logger.log("Generated private key")
    public_key = private_key.public_key()
    logger.log("Generated public key")

    # Send public_key to other peer
    channel.r2e.put(public_key)

    # Receive other peer's public_key
    peer_public_key = channel.e2r.get()

    # Derive shared key
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_key)

    ##### End Diffie-Hellman Key Exchange ####

    logger.log(derived_key)

    #msg = channel.e2r.get()
    #logger.received(msg)
    #msg = b"Ack"
    #channel.r2e.put(msg)
    #logger.sent(msg)

#pwd = bytes(input("Shared Password > "),"utf-8")

class Channel:
    def __init__(self):
        self.e2r = Queue(5)
        self.r2e = Queue(5)

channel = Channel()

# Create emitter and receiver threads
e = Thread(target=emitter,args=(channel,))
r = Thread(target=receiver,args=(channel,))
    
# Start both threads
e.start()
r.start()

# Wait for them to finish to exit program
e.join()
r.join()
print("[INFO] > Finished program execution")
