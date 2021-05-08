#N = 509
#p = 3
#log_q = 11
#q = 1 << log_q # 2048


N = next_prime(1000)
p = 3
q = next_prime(1500)

_Z.<w>  = ZZ[]
R.<w>   = QuotientRing(_Z , _Z.ideal(w^N - 1))
#print(R)

_Q.<w>  = Integers(q)[]
Rq.<w>  = QuotientRing(_Q , _Q.ideal(w^N - 1))

def random_polyS3():
    return [choice([-1,0,1]) for i in range(N)]

_f = random_polyS3()
# print(list(_f))
f = Rq(_f)
print(list(f))
print()
# print(list(f.inverse_of_unit()))

# fp = [ lift(Mod(a,3)) for a in f ]
# print(list(fp))
