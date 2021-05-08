q = 3329
n = 256
n_prime = 9
n1 = 3
n2 = 2

(du,dv) = (10,4)
sigma = 2^(-139)

_Z.<w>  = ZZ[]
R.<w>   = QuotientRing(_Z , _Z.ideal(w^N - 1))

_Q.<w>  = Integers(q)[]
Rq.<w>  = QuotientRing(_Q , _Q.ideal(w^N - 1))

class KyberPKE:
    def __init__(self):
        self.q = 3329
        self.n = 256