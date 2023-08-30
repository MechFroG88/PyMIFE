from Crypto.Util.number import isPrime
from random import randrange
from math import isqrt


def inner_product(x, y):
    if len(x) != len(y):
        raise Exception("Length of inner product different")
    return sum([x[i] * y[i] for i in range(len(x))])


# Referenced from https://github.com/sagemath/sagelib/blob/fd0c7c46e6a2da4b84df582e0da0333ce5cf79d9/sage/groups/generic.py#L824

def discrete_log_bound(p, a, g, bounds):
    width = bounds[1] - bounds[0]
    if width < 1000:
        return discrete_log_bound_brute(p, a, g, bounds)

    lb = bounds[0]
    ub = bounds[1]

    N = isqrt(width) + 1

    M = {}
    for iterations in range(10):
        # random walk function setup
        k = 0
        while 2**k < N:
            r = randrange(1, N)
            M[k] = (r, pow(g, r, p))
            k += 1

        # first random walk
        H = pow(g, ub, p)
        c = ub
        for i in range(N):
            r, e = M[hash(H) % k]
            H = (H * e) % p
            c += r

        mem = {H}

        # second random walk
        H = a
        d = 0
        while c-d >= lb:
            if ub > c-d and H in mem:
                return c-d
            r, e = M[hash(H) % k]
            H = (H * e) % p
            d += r

    return discrete_log_bound_brute(p, a, g, bounds)


def discrete_log_bound_brute(p, a, g, bounds):
    if not isPrime(p):
        raise Exception("p must be a prime number")
    cul = pow(g, bounds[0], p)
    for i in range(bounds[1] - bounds[0] + 1):
        if cul == a:
            ans = i + bounds[0]
            return ans if ans < p else ans % (p - 1)
        cul = (cul * g) % p
    raise Exception(f"Discrete log for {a} under base {g} not found in bounds ({bounds[0]}, {bounds[1]})")


def to_group(p, g):
    return lambda x: pow(g, int(x), p)
