Z = PolynomialRing(QQ,'w')
# R = QuotientRing(ZZ[x], x**8+1)
w = Z.gen()

msg = 'Hello Cruel World!'

def int_to_poly(c):
    poly = 0
    i = 0
    while (2**i <= c):
        poly += ((c >> i) % 2)*w^i
        i += 1
    return poly

def msgs_to_polys(msg):
    return [int_to_poly(ord(c)) for c in msg]

def re_modulo(num,div,modby):
    [_,remain] = num / div #poly.divPoly(num,div)
    return remain % modby #poly.modPoly(remain,modby)

def centered(c,q):
    u = float(q)/float(2)
    l = -u
    c = c % q
    c = map(lambda x: mod(x,q*-1*(x > u)), c)
    return c

class NTRU:
    def __init__(self, N, p, q):
        self.N = N
        self.p = p
        self.q = q
        self.D = w^N - 1

    def gen_pubkey(self, f, g, d):
        self.f = f
        self.g = g
        self.d = d
        [gcd_f,s_f,t_f] = self.f.xgcd(g)
        self.f_p = s_f % self.p #poly.modPoly(s_f,self.p)
        self.f_q = s_f % self.q #poly.modPoly(s_f,self.q)
        self.h = re_modulo(self.f_q * self.g, self.D, self.q) #self.h=self.reModulo(poly.multPoly(self.f_q,self.g),self.D,self.q)

    def encrypt(self, msg, rand_poly):
        e_tilda =  ((self.p * rand_poly) * self.h) + msg #poly.addPoly(poly.multPoly(poly.multPoly([self.p],randPol),self.h),message)
        e = re_modulo(e_tilda, self.D, self.q) #self.reModulo(e_tilda,self.D,self.q)
        return e

    def decrypt(self, enc):
        tmp = re_modulo(self.f * enc, self.D, self.q) # tmp=self.reModulo(poly.multPoly(self.f,encryptedMessage),self.D,self.q)
        centered = centered(tmp, self.q)
        m1 = self.f_p * centered # m1=poly.multPoly(self.f_p,centered)
        tmp = re_modulo(m1, self.D, self.p) # tmp=self.reModulo(m1,self.D,self.p)
        return tmp


####################################################

#print(msgs_to_polys(msg))

bob = NTRU(7,29,491531)
f = +w^0 -w^1 -w^3 +w^4 +w^5
g = -w^0 +w^3 +w^4 -w^6
d = 2
bob.gen_pubkey(f,g,d)
msg = int_to_poly(97)
print(msg)
enc = bob.encrypt(msg)
bob.decrypt(enc)
print()
#q, u, v = f.xgcd(g)
