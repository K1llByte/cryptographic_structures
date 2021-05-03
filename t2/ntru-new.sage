
from random import choice

N = next_prime(1000)
Q = next_prime(1500)
T = N//4

_Z.<w>  = ZZ[]
R.<w>   = QuotientRing(_Z , _Z.ideal(w^N - 1))

_Q.<w>  = Integers(Q)[]
Rq.<w>  = QuotientRing(_Q , _Q.ideal(w^N - 1))





# Conversão polinomio -> vetor -> polinomio

def _toZ(f,p=None):
    ff = list(f)
    if p == None:
        return ff
    else:
        fp = map(lift,[Mod(a,p) for a in ff])
        return [u if u <= p//2 else u-p for u in fp ]

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
        # self.D = w^N - 1
        while True:
            f = _toR(random_poly())
            g = _toR(random_poly())
            h = _h(f,g)
            if h == None:
                break

    def random_poly():
        return [rn.choice([-1,0,1]) for i in range(self.N)]