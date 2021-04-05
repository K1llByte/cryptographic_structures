import hashlib

def digest(msg):
    msg = msg.encode("utf-8")
    return Integer('0x' + hashlib.sha1(msg).hexdigest())

class DSA_Error(Exception):
    pass

class DSA:

    ####### Constants #######

    FULL = 0
    PUBLIC_KEY = 1
    
    ####### Constructors #######

    def __init__(self,L,N):

        # FIPS 186-4 Possible L,N combinations (source: wikipedia):
        _LN_COMBINATIONS = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
        if not ((L,N) in _LN_COMBINATIONS):
            raise DSA_Error("Invalid key length pair")
        
        ########### Parameters ###########

        # Choose an N-bit prime q
        #self.q = random_prime(2 ^ N)
        self.q = 1193447034984784682329306571139467195163334221569
        # Choose an L-bit prime p such that p-1 is a multiple of q
        self.p = 89884656743115796742429711405763364460177151692783429800884652449310979263752253529349195459823881715145796498046459238345428121561386626945679753956400077352882071663925459750500807018254028771490434021315691357123734637046894876123496168716251735252662742462099334802433058472377674408598573487858308054417
        #self.p = random_prime(2 ^ N) # TODO: Wrong
        # Choose an integer h randomly from {2...p-2}
        h = randint(2, self.p-2)
        # Compute g = h ^ ((p-1)/p) mod p
        self.g = mod(h ^ ((self.p-1) // self.p), self.p)

        ###### Public & Private Key ######

        # Choose an integer x randomly from {1...q-1}
        self.x = randint(1,self.q-1)
        # Compute y = g ^ x mod p
        self.y = self.g ^ self.x % self.p

        self.INITIALIZATION = DSA.FULL

    @classmethod
    def from_public_key(cls,LN,pqgy):
        instance = cls(LN[0],LN[1])
        instance.p = pqgy[0]
        instance.q = pqgy[1]
        instance.g = pqgy[2]
        instance.y = pqgy[3]
        instance.INITIALIZATION = DSA.PUBLIC_KEY


    ######## Getters ########

    def parameters(self):
        return (self.p,self.q,self.g)

    def public_key(self):
        return self.y

    ##### Sign & Verify #####

    def sign(self,m):
        if self.INITIALIZATION == DSA.FULL:
            k = randint(1, self.q-1)
            r = 0
            while r == 0:
                r = mod(power_mod(self.g,k,self.p), self.q)
                s = mod(((digest(m) + self.x*r) // k), self.q)
            return (r,s)
        #else:
        raise DSA_Error("DSA instance only with public key, signing not avaiable")

    def verify(self,m,rs):
        r = rs[0]
        s = rs[1]
        print("q",self.q)
        if (0 < r and r < self.q) and (0 < s and s < self.q):
            w = power_mod(s,-1,self.q)
            u1 = mod(digest(m) * w, self.q)
            u2 = mod(r * w, self.q)
            v = mod(self.g ^ u1 * self.g ^ u2, self.q)
            return v == r
        print("nem sequer")
        return False

dsa = DSA(1024,160)
m = "hello cruel world"
rs = dsa.sign(m)
print(rs)
print(dsa.verify(m,rs))


####################################################################################################
import hashlib

def digest(msg):
    msg = msg.encode("utf-8")
    return Integer('0x' + hashlib.sha1(msg).hexdigest())


class ECDSA:
    ####### Constructors #######
    
    def __init__(self):
        # link auxiliar: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
        # Curva e parameterização P192
        self.F = FiniteField(2**192 - 2**64 - 1)
        b  = 0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
        E  = EllipticCurve(self.F, [-3, b])
        self.G = E((0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811))
        # order n
        self.n  = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
        self.Fn = FiniteField(self.n)

        self.d = randint(1, self.n - 1)
        self.Q = self.d * self.G

    ######## Getters ########

    def public_key(self):
        return self.Q

    def sign(self, m):
        r = 0
        s = 0
        while s == 0:
            k = 1
            while r == 0:
                k = randint(1, self.n - 1)
                n_Q = k * self.G
                (x1, y1) = n_Q.xy()
                r = self.Fn(x1)
            kk = self.Fn(k)
            e = digest(m)
            s = kk ^ (-1) * (e + self.d * r)
        return [r, s]

    ##### Sign & Verify #####

    def verify(self, m, rs):
        r = rs[0]
        s = rs[1]
        e = digest(m)
        w = s ^ (-1)
        u1 = (e * w)
        u2 = (r * w)
        P1 = Integer(u1) * self.G
        P2 = Integer(u2) * self.Q
        X = P1 + P2
        (x, y) = X.xy()
        v = self.Fn(x)
        return v == r


ecdsa = ECDSA()
m = "hello cruel world"
rs = ecdsa.sign(m)
print(ecdsa.verify(m, rs))