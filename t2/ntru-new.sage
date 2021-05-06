from random import choice

N = next_prime(1000)
p = 3
q = next_prime(1500)

_Z.<w>  = ZZ[]
R.<w>   = QuotientRing(_Z , _Z.ideal(w^N - 1))
#print(R)

_Q.<w>  = Integers(q)[]
Rq.<w>  = QuotientRing(_Q , _Q.ideal(w^N - 1))
#print(Rq)

# Mensagem é dada num intervalo de coeficientes [0, q-1],
# por isso o modulo dos valores tem de ser recentrados
# para o intervalo [-q/2, q/2].b
def centered(l,p):
    fp = [ lift(Mod(a,p)) for a in l ]
    return [u if (u <= p//2) else u-p for u in fp ]

def to_list(f):
    return list(f)

class NTRU:
    def __init__(self, N, p, q):
        self.N = N
        self.p = p
        self.q = q
        while True:
            self.f = 1 + self.p * R(self.random_poly())
            self.g = self.p * R(self.random_poly())
            try:
                fq = Rq(to_list(self.f)).inverse_of_unit()
                hq = fq * Rq(to_list(self.g))
                self.h = R([lift(a) for a in list(hq)])
                break
            except ZeroDivisionError:
                pass

    def encrypt(self, msg):
        r = R(self.random_poly())
        m = R(msg)
        return centered(to_list(self.h*r + m), self.q)

    def decrypt(self, enc):
        e = R(enc)
        a = centered(to_list(self.f * e), self.q)
        return centered(to_list(R(a)),self.p)

    def random_poly(self):
        return [choice([-1,0,1]) for i in range(self.N)]

bob = NTRU(N,p,q)
msg = bob.random_poly()
enc = bob.encrypt(msg)
dec = bob.decrypt(enc)
print(msg == dec)