from cryptography.hazmat.primitives.hashes import (Hash, SHAKE256)


def prg(password: bytes, n: int) -> bytes:
    alg = Hash(SHAKE256(8*n)) # 64 bits == 8 bytes
    alg.update(password)
    return alg.finalize()

def bytes_xor(a: bytes, b: bytes):
    if len(a) != len(b):
        raise ValueError("bytes arguments must have the same length")
    return bytes([_a ^ _b for _a, _b in zip(a, b)])

def encrypt(plaintext: bytes, key: bytes):
    return bytes_xor(plaintext,key)

def decrypt(ciphertext: bytes, key: bytes):
    return bytes_xor(ciphertext,key)


key = prg(b"ola mundo cruel",1)

print("len(key):",len(key))
print("key:",key)

ct = encrypt(b"olaolaol",key)
msg = decrypt(ct,key)

print("len(ct):",len(ct))
print("ct:",ct)

print("len(msg):",len(msg))
print("msg:",msg)