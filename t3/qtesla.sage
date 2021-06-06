import os
from cryptography.hazmat.primitives import hashes


class pI:
    n = 1024
    sigma = 8.5
    q = 343576577
    h = 25
    Le = 554
    Ls = 554
    B = 2^19 - 1
    d = 22
    k = 4

class pIII:
    n = 2048
    sigma = 8.5
    q = 856145921
    h = 40
    Le = 901
    Ls = 901
    B = 2^21 - 1
    d = 24
    k = 5


class qTesla:
    def __init__(self, params=pI):
        # Define Parameters
        self.n = params.n
        self.sigma = params.sigma
        self.q = params.q
        self.h = params.h
        self.Le = params.Le
        self.Ls = params.Ls
        self.B = params.B
        self.d = params.d
        self.k = params.k
        self.K = 256
        self.alfa = self.sigma / self.q

        # Define Fields
        Zx.<x> = ZZ[]
        R.<x> = Zx.quotient(x^self.n+1)
        self.R = R
        Zq.<z> = GF(self.q)[]
        Rq.<z> = Zq.quotient(z^self.n+1)
        self.Rq = Rq

        # Generate Keys
        counter = 1
        pre_seed = os.urandom(self.K // 8)
        seed_s, seeds_e, seed_a, seed_y = self.prf1(pre_seed)
        a = self.genA(seed_a)
        
        while True:
            s = self.GaussSampler(seed_s, counter)
            counter += 1
            if self.checkS(s):
                break
        
        e = []
        t = []
        for i in range(self.k):
            while True:
                e_i = self.GaussSampler(seeds_e[i], counter)
                counter += 1
                if self.checkE(e_i):
                    e.append(e_i)
                    break
            t.append(a[i] * s + e[i]) 
        
        self.g = self.G(t)
        # Public Key : (t, seed_a)
        # Private Key :  (s, e, seed_a, seed_y, g)


    def sign(self, m):
        pass

    def verify(self, m, sig):
        pass
        
    ########### Auxiliar Functions ###########

    # FIXME: Possivelmente mal defenido
    def checkE(self, e):
        my_sum = 0
        e_list = list(e)
        e_list.sort(reverse=True)
        for i in range(0,self.h):
            my_sum += e_list[i]

        return (my_sum > self.Le)

    # FIXME: Possivelmente mal defenido
    def checkS(self, s):
        my_sum = 0
        s_list = list(s)
        s_list.sort(reverse=True)
        for i in range(0,self.h):
            my_sum += s_list[i]

        return (my_sum > self.Ls)


    def prf1(self, pre_seed):
        elem = 3 + self.k
        xof = hashes.Hash(hashes.SHAKE256(int(self.K*(self.k + 3)/8)))
        xof.update(pre_seed)
        seed = xof.finalize()

        seed_s = seed[0:32]
        seeds_e = [ seed[32*i:32*(i+1)] for i in range(1,self.k+1)]
        seed_a = seed[self.k+1:self.k+2]
        seed_y = seed[self.k+2:self.k+3]

        return seed_s, seeds_e, seed_a, seed_y

    def genA(self, seed_a):
        # Convert seed_a to int and set seed for
        # sagemath's random generator
        set_random_seed(int.from_bytes(seed_a, "big"))
        return [ self.Rq.random_element() for _ in range(self.k) ]

    def GaussSampler(self, seed_s, nounce):
        seed_nounce = int.from_bytes(seed_s, "big") + nounce
        set_random_seed(seed_nounce)

        # If the distribution 'gaussian' is specified, 
        # the output is sampled from a discrete Gaussian
        # distribution with parameter σ=x
        #return self.R.random_element(x=self.sigma,distribution='gaussian')
        return self.Rq.random_element(x=self.sigma,distribution='gaussian')

    def G(self, m):
        if type(m) == list:
            # Convert poly to bytes form
            m = b''.join([ b''.join([ int(p).to_bytes(4,"big") for c in p ]) for p in m ])
        
        xof = hashes.Hash(hashes.SHAKE256(int(40)))
        xof.update(m)
        return xof.finalize()

        

    
qtesla = qTesla(pI)


############## Testing ##############

#Zq.<z> = GF(pI.q)[]
#Rq.<z> = Zq.quotient(z^pI.n+1)