from random import randrange
from math import isqrt


def inner_product(x, y, identity=0):
    """
    Compute the inner product of two vectors

    :param x: First vector
    :param y: Second vector
    :param identity: Identity element of the inner product
    :return: Inner product of the two vectors
    """
    if len(x) != len(y):
        raise Exception("Length of inner product different")
    return sum([x[i] * y[i] for i in range(len(x))], start=identity)


# Referenced from https://github.com/sagemath/sagelib/blob/fd0c7c46e6a2da4b84df582e0da0333ce5cf79d9/sage/groups/generic.py#L824

def discrete_log_bound(a, g, bounds):
    """
    Find the discrete log of a under base g within bounds using Pollard's Kangaroo algorithm

    :param a: Target element
    :param g: Base element
    :param bounds: Bounds for discrete log search
    :return: Discrete log of a under base g
    """
    width = bounds[1] - bounds[0]
    if width < 1000:
        return discrete_log_bound_brute(a, g, bounds)

    lb = bounds[0]
    ub = bounds[1]

    N = isqrt(width) + 1

    M = {}
    for iterations in range(10):
        # random walk function setup
        k = 0
        while 2 ** k < N:
            r = randrange(1, N)
            M[k] = (r, r * g)
            k += 1

        # first random walk
        H = ub * g
        c = ub
        for i in range(N):
            r, e = M[hash(H) % k]
            H = H + e
            c += r

        ori = H

        # second random walk
        H = a
        d = 0
        while c - d >= lb:
            if ub > c - d and H == ori:
                return c - d
            r, e = M[hash(H) % k]
            H = H + e
            d += r

    return discrete_log_bound_brute(a, g, bounds)


def discrete_log_bound_brute(a, g, bounds):
    """
    Find the discrete log of a under base g within bounds using brute force

    :param a: Target element
    :param g: Base element
    :param bounds: Bounds for discrete log search
    :return: Discrete log of a under base g
    """
    cul = bounds[0] * g
    for i in range(bounds[1] - bounds[0] + 1):
        if cul == a:
            ans = i + bounds[0]
            return ans
        cul = (cul + g)
    raise Exception(f"Discrete log for {a} under base {g} not found in bounds ({bounds[0]}, {bounds[1]})")
