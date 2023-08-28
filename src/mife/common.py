from Crypto.Util.number import isPrime


def inner_product(x, y):
    if len(x) != len(y):
        raise Exception("Length of inner product different")
    return sum([x[i] * y[i] for i in range(len(x))])


def discrete_log_bound(p, a, g, bounds):
    if not isPrime(p):
        raise Exception("p must be a prime number")
    cul = pow(g, bounds[0], p)
    for i in range(bounds[1] - bounds[0] + 1):
        if cul == a:
            return (i + bounds[0]) % (p - 1)
        cul = (cul * g) % p
    raise Exception(f"Discrete log for {a} under base {g} not found in bounds ({bounds[0]}, {bounds[1]})")


def to_group(p, g):
    return lambda x: pow(g, int(x), p)
