from secrets import randbits, randbelow
from Crypto.Util.number import getStrongPrime, inverse
from typing import List, Tuple

from src.mife.common import inner_product, discrete_log_bound
from src.mife.data.zmod import Zmod
from src.mife.data.group import GroupBase, GroupElem

# https://eprint.iacr.org/2015/017.pdf

class _FeDDH_MK:
    def __init__(self, g: GroupElem, n: int, F: GroupBase, **kwargs):
        self.g = g
        self.n = n
        self.F = F
        self.msk = kwargs.get('msk')
        self.mpk = kwargs.get('mpk')

    def has_private_key(self) -> bool:
        return self.msk is not None


class _FeDDH_SK:
    def __init__(self, y: List[int], sk: int):
        self.y = y
        self.sk = sk

class _FeDDH_C:
    def __init__(self, g_r: GroupElem, c: List[GroupElem]):
        self.g_r = g_r
        self.c = c


class FeDDH:
    @staticmethod
    def generate(n: int, F: GroupBase = None) -> _FeDDH_MK:
        if F is None:
            F = Zmod(getStrongPrime(1024))
        g = F.generator()
        msk = [randbelow(F.order()) for _ in range(n)]
        mpk = [msk[i] * g for i in range(n)]

        return _FeDDH_MK(g, n, F, msk=msk, mpk=mpk)

    @staticmethod
    def encrypt(x: List[int], pub: _FeDDH_MK) -> _FeDDH_C:
        if len(x) != pub.n:
            raise Exception("Encrypt vector must be of length n")
        r = randbelow(pub.F.order())
        g_r = r * pub.g
        c = [r * pub.mpk[i] + x[i] * pub.g for i in range(pub.n)]
        return _FeDDH_C(g_r, c)

    @staticmethod
    def decrypt(c: _FeDDH_C, pub: _FeDDH_MK, sk: _FeDDH_SK, bound: Tuple[int, int]) -> int:
        cul = pub.F.identity()
        for i in range(pub.n):
            cul = cul + sk.y[i] * c.c[i]
        cul = cul - sk.sk * c.g_r
        return discrete_log_bound(cul, pub.g, bound)

    @staticmethod
    def keygen(y: List[int], key: _FeDDH_MK) -> _FeDDH_SK:
        if len(y) != key.n:
            raise Exception(f"Function vector must be of length {key.n}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        sk = inner_product(key.msk, y)
        return _FeDDH_SK(y, sk)
