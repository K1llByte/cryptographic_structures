Z = PolynomialRing(ZZ,'w')
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

class NTRU:
    def __init__(self,N,p,q):
        pass

    def encrypt(self, msg, rand_poly):
        pass

    def decrypt(self, enc):
        pass

####################################################

print(msgs_to_polys(msg))

bob = NTRU(7,29,491531)
f = +w^0 -w^1 -w^3 +w^4 +w^5
g = -w^0 +w^3 +w^4 -w^6
