from threading import Thread
from queue import Queue
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Diffie-Hellman & DSA
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat, PublicFormat

DH_AND_DSA = 0
ECDH_AND_ECDSA = 1
# THIS VARIABLE DEFINES WHICH METHOD WILL BE
# USED FOR KEY EXCHAGE
key_exchange_method = ECDH_AND_ECDSA

class Channel:
    def __init__(self):
        self.e2r = Queue(5)
        self.r2e = Queue(5)

class Logger:
    def __init__(self,name):
        self.thread_name = name

    def sent(self,msg):
        print("[{}] Sent > {}".format(self.thread_name,msg))

    def received(self,msg):
        print("[{}] Received > {}".format(self.thread_name,msg))

    def log(self,msg):
        print("[{}] > {}".format(self.thread_name,msg))


def encrypt(message,key):
    # Encrypt-and-MAC method
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    mac = h.finalize()

    # AES CTR mode
    nounce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nounce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    return (nounce,ciphertext,mac)

def decrypt(nounce_ciphertext_mac,key):
    nounce = nounce_ciphertext_mac[0]
    ciphertext = nounce_ciphertext_mac[1]
    mac = nounce_ciphertext_mac[2]

    cipher = Cipher(algorithms.AES(key), modes.CTR(nounce))
    decryptor = cipher.decryptor()
    message = decryptor.update(ciphertext) + decryptor.finalize()
    
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    h.verify(mac)
    
    return message


# Diffie-Hellman Key Exchange
def emitter_key_exchange(channel,logger):
    global emitter_private_key
    global receiver_public_key
    # Emiter generates some DH parameters and sends to Receiver
    parameters = dh.generate_parameters(generator=2, key_size=1024)
    logger.log("Generated parameters")

    signature = emitter_private_key.sign(
        parameters.parameter_bytes(Encoding.DER,ParameterFormat.PKCS3),
        hashes.SHA256()
    )
    channel.e2r.put((parameters,signature))
    logger.sent("DH parameters")

    # Entities generate both private and public keys
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    logger.log("Generated private and public key")
        
    # Send public_key to other peer
    signature = emitter_private_key.sign(
        public_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo),
        hashes.SHA256()
    )
    channel.e2r.put((public_key,signature))

    # Receive other peer's public_key
    peer_public_key, signature = channel.r2e.get()
    try:
        receiver_public_key.verify(
            signature,
            peer_public_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo),
            hashes.SHA256()
        )
    except InvalidSignature:
        logger.log("Invalid signature for Peer Public Key")

    # Derive shared key
    shared_key = private_key.exchange(peer_public_key)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    ).derive(shared_key)

    return key

# Elliptic Curve Key Exchange
def emitter_ec_key_exchange(channel,logger):
    global emitter_private_key
    global receiver_public_key

    # Entities generate both private and public key
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    logger.log("Generated private and public key")

    # Send public_key to other peer
    signature = emitter_private_key.sign(
        public_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo),
        ec.ECDSA(hashes.SHA256())
    )
    channel.e2r.put((public_key,signature))

    # Receive other peer's public_key
    peer_public_key, signature = channel.r2e.get()
    try:
        receiver_public_key.verify(
            signature,
            peer_public_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo),
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        logger.log("Invalid signature for Peer Public Key")

    # Derive shared key
    shared_key = private_key.exchange(ec.ECDH(),peer_public_key)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    ).derive(shared_key)

    return key


# Emitter thread function
def emitter(channel):
    logger = Logger("Emitter")
    logger.log("Logger initialized")

    if key_exchange_method == DH_AND_DSA:
        key = emitter_key_exchange(channel,logger)
    if key_exchange_method == ECDH_AND_ECDSA:
        key = emitter_ec_key_exchange(channel,logger) 
    logger.log(key)

    msg = b"Hello World!"
    nounce_ct = encrypt(msg,key)
    logger.log("Encrypted: {}".format(nounce_ct))
    channel.e2r.put(nounce_ct)



# Diffie-Hellman Key Exchange
def receiver_key_exchange(channel,logger):
    global receiver_private_key
    global emitter_public_key

    # Get Emitter DH parameters
    parameters, signature = channel.e2r.get()
    try:
        emitter_public_key.verify(
            signature,
            parameters.parameter_bytes(Encoding.DER,ParameterFormat.PKCS3),
            hashes.SHA256()
        )
    except InvalidSignature:
        logger.log("Invalid signature for DH parameters")
    logger.received("DH parameters")
    
    # Entities generate both private and public key
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    logger.log("Generated private and public key")

    # Send public_key to other peer
    signature = receiver_private_key.sign(
        public_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo),
        hashes.SHA256()
    )
    channel.r2e.put((public_key,signature))

    # Receive other peer's public_key
    peer_public_key, signature = channel.e2r.get()
    try:
        emitter_public_key.verify(
            signature,
            peer_public_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo),
            hashes.SHA256()
        )
    except InvalidSignature:
        logger.log("Invalid signature for Peer Public Key")

    # Derive shared key
    shared_key = private_key.exchange(peer_public_key)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    ).derive(shared_key)

    return key


# Elliptic Curve Key Exchange
def receiver_ec_key_exchange(channel,logger):
    global receiver_private_key
    global emitter_public_key

    # Entities generate both private and public key
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    logger.log("Generated private and public key")

    # Send public_key to other peer
    signature = receiver_private_key.sign(
        public_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo),
        ec.ECDSA(hashes.SHA256())
    )
    channel.r2e.put((public_key,signature))

    # Receive other peer's public_key
    peer_public_key, signature = channel.e2r.get()
    try:
        emitter_public_key.verify(
            signature,
            peer_public_key.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo),
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        logger.log("Invalid signature for Peer Public Key")

    # Derive shared key
    shared_key = private_key.exchange(ec.ECDH(),peer_public_key)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    ).derive(shared_key)

    return key


# Receiver thread function
def receiver(channel):
    logger = Logger("Receiver")
    logger.log("Logger initialized")

    if key_exchange_method == DH_AND_DSA:
        key = receiver_key_exchange(channel,logger)
    elif key_exchange_method == ECDH_AND_ECDSA:
        key = receiver_ec_key_exchange(channel,logger)
    
    logger.log(key)

    nounce_ct = channel.e2r.get()
    try:
        message = decrypt(nounce_ct,key)
        logger.log("Decrypted: {}".format(message))
    except InvalidSignature:
        logger.log("Invalid MAC")





if key_exchange_method == DH_AND_DSA:
    emitter_private_key = dsa.generate_private_key(key_size=1024)
    receiver_private_key = dsa.generate_private_key(key_size=1024)
elif key_exchange_method == ECDH_AND_ECDSA:
    emitter_private_key = ec.generate_private_key(ec.SECP384R1())
    receiver_private_key = ec.generate_private_key(ec.SECP384R1()) #

emitter_public_key = emitter_private_key.public_key()
receiver_public_key = receiver_private_key.public_key()

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
