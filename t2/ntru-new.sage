from random import choice

N = next_prime(1000)
p = 3
q = next_prime(1500)
T = N//4

_Z.<w>  = ZZ[]
R.<w>   = QuotientRing(_Z , _Z.ideal(w^N - 1))

_Q.<w>  = Integers(q)[]
Rq.<w>  = QuotientRing(_Q , _Q.ideal(w^N - 1))



def _toZ(f,p=None):
    ff = list(f)
    if p == None:
        return ff
    else:
        fp = [ lift(Mod(a,p)) for a in ff ]
        return [u if (u <= p//2) else u-p for u in fp ]

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
            self.f = 1 + self.p * _toR(self.random_poly())
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
        return _toZ(_toR(a), p=self.p+1)

    def random_poly(self):
        return [choice([-1,0,1]) for i in range(self.N)]

bob = NTRU(N,p,q)
msg = bob.random_poly()
enc = bob.encrypt(msg)
dec = bob.decrypt(enc)

print("msg",msg)
print("dec",dec)
print(dec == msg)