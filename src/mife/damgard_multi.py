from secrets import randbits, randbelow
from Crypto.Util.number import getStrongPrime, inverse
from typing import List, Tuple
from sympy import Matrix, matrix_multiply_elementwise

from src.mife.common import inner_product, discrete_log_bound, to_group

# https://eprint.iacr.org/2017/972.pdf


class _FeDamgardMulti_MPK:

    def __init__(self, a: Matrix, wa: Matrix):
        self.a = a
        self.wa = wa

class _FeDamgardMulti_MSK:

    def __init__(self, w: Matrix, u: Matrix):
        self.w = w
        self.u = u

class _FeDamgardMulti_MK:
    def __init__(self, g: int, n: int, m: int, p: int, msk: _FeDamgardMulti_MSK, mpk: _FeDamgardMulti_MPK):
        self.g = g
        self.n = n
        self.m = m
        self.p = p
        self.msk = msk
        self.mpk = mpk
        self.to_group = to_group(self.p, self.g)

    def has_private_key(self) -> bool:
        return self.msk is not None


class _FeDamgardMulti_SK:
    def __init__(self, y: List[List[int]], d: List[Matrix], z: int):
        self.y = y
        self.d = d
        self.z = z


class _FeDamgardMulti_C:
    def __init__(self, t: Matrix, c: Matrix, index: int):
        self.t = t
        self.c = c
        self.index = index

class FeDamgardMulti:
    @staticmethod
    def generate(n: int, m: int, bits: int) -> _FeDamgardMulti_MK:
        g = 2
        p = getStrongPrime(bits)
        a = randbelow(p)
        a_v = Matrix([1, a])
        W = Matrix([[randbelow(p), randbelow(p)] for _ in range(m)])
        u = Matrix([[randbelow(p) for _ in range(m)] for _ in range(n)])

        msk = _FeDamgardMulti_MSK(W, u)
        mpk = _FeDamgardMulti_MPK(
            a_v.applyfunc(to_group(p, g)),
            (W * a_v).applyfunc(to_group(p, g))
        )

        return _FeDamgardMulti_MK(g, n, m, p, msk=msk, mpk=mpk)

    @staticmethod
    def encrypt(x: List[int], i: int, key: _FeDamgardMulti_MK) -> _FeDamgardMulti_C:
        if len(x) != key.m:
            raise Exception(f"Encrypt vector must be of length {key.m}")
        if not(0 <= i < key.n):
            raise Exception(f"Index of vector must be within [0,{key.n})")

        x = Matrix(x)
        r = randbelow(key.p)

        t = key.mpk.a.applyfunc(lambda g: pow(g, r, key.p))

        c = matrix_multiply_elementwise(
            (x + key.msk.u.row(i).T).applyfunc(key.to_group),
            key.mpk.wa.applyfunc(lambda g: pow(g, r, key.p))
        )

        return _FeDamgardMulti_C(t, c, i)

    @staticmethod
    def decrypt(c: List[_FeDamgardMulti_C], key: _FeDamgardMulti_MK, sk: _FeDamgardMulti_SK, bound: Tuple[int, int]) -> int:
        cul = 1
        for i in range(key.n):
            if c[i].index != i:
                raise Exception(f"Ciphertext index incorrect")

            # [y_i dot c_i]
            yc = 1
            for j in range(key.m):
                yc = (yc * pow(c[i].c[j], sk.y[i][j], key.p)) % key.p

            # [d_i dot t_i]
            dt = (pow(c[i].t[0], sk.d[i][0], key.p) * pow(c[i].t[1], sk.d[i][1], key.p)) % key.p

            cul = (cul * yc * inverse(dt, key.p)) % key.p

        cul = (cul * inverse(key.to_group(sk.z), key.p)) % key.p
        return discrete_log_bound(key.p, cul, key.g, bound)

    @staticmethod
    def keygen(y: List[List[int]], key: _FeDamgardMulti_MK) -> _FeDamgardMulti_SK:
        if len(y) != key.n:
            raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
        d = []
        z = 0
        for i in range(key.n):
            if len(y[i]) != key.m:
                raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
            d.append(Matrix(y[i]).T * key.msk.w)
            z += Matrix(y[i]).dot(key.msk.u.row(i))

        return _FeDamgardMulti_SK(y, d, z)
