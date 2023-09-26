from secrets import randbelow
from Crypto.Util.number import getStrongPrime
from typing import List, Tuple

from src.mife.data import Matrix
from src.mife.common import discrete_log_bound, inner_product

from src.mife.data import GroupBase, GroupElem
from src.mife.data import Zmod


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
    def __init__(self, g: GroupElem, n: int, m: int, F: GroupBase, msk: _FeDamgardMulti_MSK, mpk: _FeDamgardMulti_MPK):
        self.g = g
        self.n = n
        self.m = m
        self.F = F
        self.to_group = lambda x: x * self.g
        self.msk = msk
        self.mpk = mpk

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
    def generate(n: int, m: int, F: GroupBase = None) -> _FeDamgardMulti_MK:
        if F is None:
            F = Zmod(getStrongPrime(1024))
        g = F.generator()
        a_v = Matrix([1, randbelow(F.order())])
        W = Matrix([[randbelow(F.order()), randbelow(F.order())] for _ in range(m)])
        u = Matrix([[randbelow(F.order()) for _ in range(m)] for _ in range(n)])

        to_group = lambda x: x * g

        msk = _FeDamgardMulti_MSK(W, u)
        mpk = _FeDamgardMulti_MPK(a_v.apply_func(to_group), (W * a_v.T).apply_func(to_group))

        return _FeDamgardMulti_MK(g, n, m, F, msk=msk, mpk=mpk)

    @staticmethod
    def encrypt(x: List[int], i: int, key: _FeDamgardMulti_MK) -> _FeDamgardMulti_C:
        if len(x) != key.m:
            raise Exception(f"Encrypt vector must be of length {key.m}")
        if not (0 <= i < key.n):
            raise Exception(f"Index of vector must be within [0,{key.n})")

        x = Matrix(x)
        r = randbelow(key.F.order())

        t = r * key.mpk.a

        c = (x + key.msk.u.row(i)).apply_func(key.to_group) + (r * key.mpk.wa).T

        return _FeDamgardMulti_C(t, c, i)

    @staticmethod
    def decrypt(c: List[_FeDamgardMulti_C], key: _FeDamgardMulti_MK, sk: _FeDamgardMulti_SK,
                bound: Tuple[int, int]) -> int:
        cul = key.F.identity()
        for i in range(key.n):
            if c[i].index != i:
                raise Exception(f"Ciphertext index incorrect")

            # [y_i dot c_i]
            yc = inner_product(sk.y[i], c[i].c[0], identity=key.F.identity())

            # [d_i dot t_i]
            dt = inner_product(sk.d[i][0], c[i].t[0], identity=key.F.identity())

            cul = cul + yc - dt

        cul = cul - key.to_group(sk.z)
        return discrete_log_bound(cul, key.g, bound)

    @staticmethod
    def keygen(y: List[List[int]], key: _FeDamgardMulti_MK) -> _FeDamgardMulti_SK:
        if len(y) != key.n:
            raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
        d = []
        z = 0
        for i in range(key.n):
            if len(y[i]) != key.m:
                raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
            y_i = Matrix(y[i])
            d.append(y_i * key.msk.w)
            z += y_i.dot(key.msk.u.row(i))

        return _FeDamgardMulti_SK(y, d, z)
