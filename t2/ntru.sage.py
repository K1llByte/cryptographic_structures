

# This file was *autogenerated* from the file ntru.sage
from sage.all_cmdline import *   # import sage library

_sage_const_1000 = Integer(1000); _sage_const_3 = Integer(3); _sage_const_1500 = Integer(1500); _sage_const_1 = Integer(1); _sage_const_2 = Integer(2); _sage_const_0 = Integer(0)
from random import choice
from cryptography.hazmat.primitives import hashes 

N = next_prime(_sage_const_1000 )
p = _sage_const_3 
q = next_prime(_sage_const_1500 )

_Z = ZZ['w']; (w,) = _Z._first_ngens(1)
R = QuotientRing(_Z , _Z.ideal(w**N - _sage_const_1 ), names=('w',)); (w,) = R._first_ngens(1)
#print(R)

_Q = Integers(q)['w']; (w,) = _Q._first_ngens(1)
Rq = QuotientRing(_Q , _Q.ideal(w**N - _sage_const_1 ), names=('w',)); (w,) = Rq._first_ngens(1)
#print(Rq)

# Mensagem é dada num intervalo de coeficientes [0, q-1],
# por isso o modulo dos valores tem de ser recentrados
# para o intervalo [-q/2, q/2-1].
def centered(l,p):
    #print("1>",l)
    fp = [ lift(Mod(a,p)) for a in l ]
    #print("2>",fp)
    tmp = [u if (u <= p//_sage_const_2 ) else u-p for u in fp ]
    #print("3>",tmp)
    #print()
    return tmp

class NTRU:
    def __init__(self, N, p, q):
        self.N = N
        self.p = p
        self.q = q
        # KeyGen on initialization
        # f tem de ser invertivel
        while True:
            self.f = _sage_const_1  + self.p * R(self.random_polyS3())
            if Rq(list(self.f)).is_unit():
                break
        self.g = self.p * R(self.random_polyS3())
        fq = Rq(list(self.f)).inverse_of_unit()
        hq = fq * Rq(list(self.g))
        self.h = R([lift(a) for a in list(hq)])

    def encrypt(self, msg):
        r = R(self.random_polyS3())
        m = R(msg)
        return centered(list(self.h*r + m), self.q)

    def decrypt(self, enc):
        e = R(enc)
        a = centered(list(self.f * e), self.q)
        return centered(list(R(a)),self.p)

    def encapsulate(self):
        # Nome rm so como referencia à submissão
        rm = self.random_polyS3()
        sha3 = hashes.Hash(hashes.SHA3_256())
        for c in rm:
            sha3.update(bytes(c + self.p // _sage_const_2 ))
        shared_key = sha3.finalize()
        return (shared_key, self.encrypt(rm))

    def decapsulate(self,cipher):
        rm = self.decrypt(cipher)
        sha3 = hashes.Hash(hashes.SHA3_256())
        for c in rm:
            sha3.update(bytes(c + self.p // _sage_const_2 ))
        shared_key = sha3.finalize()
        return shared_key

    def random_polyS3(self):
        return [choice([-_sage_const_1 ,_sage_const_0 ,_sage_const_1 ]) for i in range(self.N)]

ntru = NTRU(N,p,q)

# NTRU PKE Test
msg = ntru.random_polyS3()
enc = ntru.encrypt(msg)
dec = ntru.decrypt(enc)
print(msg == dec)

# NTRU KEM Test
bob_shared_secret, enc = ntru.encapsulate()
alice_shared_secret = ntru.decapsulate(enc)
print(bob_shared_secret == alice_shared_secret)

