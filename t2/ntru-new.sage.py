

# This file was *autogenerated* from the file ntru-new.sage
from sage.all_cmdline import *   # import sage library

_sage_const_1000 = Integer(1000); _sage_const_3 = Integer(3); _sage_const_1500 = Integer(1500); _sage_const_4 = Integer(4); _sage_const_1 = Integer(1); _sage_const_2 = Integer(2); _sage_const_0 = Integer(0)
from random import choice

N = next_prime(_sage_const_1000 )
p = _sage_const_3 
q = next_prime(_sage_const_1500 )
T = N//_sage_const_4 

_Z = ZZ['w']; (w,) = _Z._first_ngens(1)
R = QuotientRing(_Z , _Z.ideal(w**N - _sage_const_1 ), names=('w',)); (w,) = R._first_ngens(1)

_Q = Integers(q)['w']; (w,) = _Q._first_ngens(1)
Rq = QuotientRing(_Q , _Q.ideal(w**N - _sage_const_1 ), names=('w',)); (w,) = Rq._first_ngens(1)



def _toZ(f,p=None):
    ff = list(f)
    if p == None:
        return ff
    else:
        fp = [ lift(Mod(a,p)) for a in ff ]
        return [u if (u <= p//_sage_const_2 ) else u-p for u in fp ]

def _toR(vec):
    return R(vec)

def _h(f,g):
    _f = Rq(_toZ(f))
    _g = Rq(_toZ(g))
    try:
        fq = _f.inverse_of_unit()
        hq = fq * _g
        return _toR([lift(a) for a in list(hq)])
    except:
        return None


class NTRU:
    def __init__(self, N, p, q):
        self.N = N
        self.p = p
        self.q = q
        while True:
            self.f = _sage_const_1  + self.p * _toR(self.random_poly())
            self.g = self.p * _toR(self.random_poly())
            self.h = _h(self.f,self.g)
            if self.h != None:
                break

    def encrypt(self, msg):
        r = _toR(self.random_poly())
        m = _toR(msg)
        return _toZ(self.h*r + m, p=self.q)

    def decrypt(self, enc):
        e = _toR(enc)
        a = _toZ(self.f * e, p=self.q)
        return _toZ(_toR(a), p=self.p+_sage_const_1 )

    def random_poly(self):
        return [choice([-_sage_const_1 ,_sage_const_0 ,_sage_const_1 ]) for i in range(self.N)]

bob = NTRU(N,p,q)
msg = bob.random_poly()
enc = bob.encrypt(msg)
dec = bob.decrypt(enc)

print("msg",msg)
print("dec",dec)
print(dec == msg)

