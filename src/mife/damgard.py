from secrets import randbits, randbelow
from Crypto.Util.number import getStrongPrime, inverse
from typing import List, Tuple

from src.mife.common import inner_product, discrete_log_bound
from src.mife.data.zmod import Zmod
from src.mife.data.group import GroupBase, GroupElem


# https://eprint.iacr.org/2015/608.pdf

class _FeDamgard_MK:
    def __init__(self, g: GroupElem, h: GroupElem, n: int, F: GroupBase, **kwargs):
        self.g = g
        self.h = h
        self.n = n
        self.F = F
        self.msk = kwargs.get('msk')
        self.mpk = kwargs.get('mpk')

    def has_private_key(self) -> bool:
        return self.msk is not None


class _FeDamgard_SK:
    def __init__(self, y: List[int], sx: int, tx: int):
        self.y = y
        self.sx = sx
        self.tx = tx


class _FeDamgard_C:
    def __init__(self, g_r: GroupElem, h_r: GroupElem, c: List[GroupElem]):
        self.g_r = g_r
        self.h_r = h_r
        self.c = c


class FeDamgard:
    @staticmethod
    def generate(n: int, F: GroupBase = None) -> _FeDamgard_MK:
        if F is None:
            F = Zmod(getStrongPrime(1024))
        while True:
            g = F.generator()
            h = F.generator()
            if g != h:
                break
        msk = [(randbelow(F.order()), randbelow(F.order())) for _ in range(n)]
        mpk = [msk[i][0] * g + msk[i][1] * h for i in range(n)]
        return _FeDamgard_MK(g, h, n, F, msk=msk, mpk=mpk)

    @staticmethod
    def encrypt(x: List[int], pub: _FeDamgard_MK) -> _FeDamgard_C:
        if len(x) != pub.n:
            raise Exception(f"Encrypt vector must be of length {pub.n}")
        r = randbelow(pub.F.order())
        g_r = r * pub.g
        h_r = r * pub.h
        c = [r * pub.mpk[i] + x[i] * pub.g for i in range(pub.n)]
        return _FeDamgard_C(g_r, h_r, c)

    @staticmethod
    def decrypt(c: _FeDamgard_C, pub: _FeDamgard_MK, sk: _FeDamgard_SK, bound: Tuple[int, int]) -> int:
        cul = pub.F.identity()
        for i in range(pub.n):
            cul = cul + sk.y[i] * c.c[i]
        cul = cul - sk.sx * c.g_r - sk.tx * c.h_r
        return discrete_log_bound(cul, pub.g, bound)

    @staticmethod
    def keygen(y: List[int], key: _FeDamgard_MK) -> _FeDamgard_SK:
        if len(y) != key.n:
            raise Exception(f"Function vector must be of length {key.n}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        sx = inner_product([key.msk[i][0] for i in range(key.n)], y)
        tx = inner_product([key.msk[i][1] for i in range(key.n)], y)
        return _FeDamgard_SK(y, sx, tx)
