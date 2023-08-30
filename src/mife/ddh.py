from secrets import randbits, randbelow
from Crypto.Util.number import getStrongPrime, inverse
from typing import List, Tuple

from src.mife.common import pow, inner_product, discrete_log_bound

# https://eprint.iacr.org/2015/017.pdf

class _FeDDH_MK:
    def __init__(self, g: int, n: int, p: int, **kwargs):
        self.g = g
        self.n = n
        self.p = p
        self.msk = kwargs.get('msk')
        self.mpk = kwargs.get('mpk')

    def has_private_key(self) -> bool:
        return self.msk is not None


class _FeDDH_SK:
    def __init__(self, y: List[int], sk: int):
        self.y = y
        self.sk = sk

class _FeDDH_C:
    def __init__(self, g_r: int, c: List[int]):
        self.g_r = g_r
        self.c = c


class FeDDH:
    @staticmethod
    def generate(n: int, bits: int) -> _FeDDH_MK:
        g = 2
        p = getStrongPrime(bits)
        msk = [randbits(bits) for _ in range(n)]
        mpk = [pow(g, msk[i], p) for i in range(n)]
        return _FeDDH_MK(g, n, p, msk=msk, mpk=mpk)

    @staticmethod
    def encrypt(x: List[int], pub: _FeDDH_MK) -> _FeDDH_C:
        if len(x) != pub.n:
            raise Exception("Encrypt vector must be of length n")
        r = randbelow(pub.p)
        g_r = pow(pub.g, r, pub.p)
        c = [(pow(pub.mpk[i], r, pub.p) * pow(pub.g, x[i], pub.p)) % pub.p for i in range(pub.n)]
        return _FeDDH_C(g_r, c)

    @staticmethod
    def decrypt(c: _FeDDH_C, pub: _FeDDH_MK, sk: _FeDDH_SK, bound: Tuple[int, int]) -> int:
        cul = 1
        for i in range(pub.n):
            cul = (cul * pow(c.c[i], sk.y[i], pub.p)) % pub.p
        cul = (cul * inverse(pow(c.g_r, sk.sk, pub.p), pub.p)) % pub.p
        return discrete_log_bound(pub.p, cul, pub.g, bound)

    @staticmethod
    def keygen(y: List[int], key: _FeDDH_MK) -> _FeDDH_SK:
        if len(y) != key.n:
            raise Exception(f"Function vector must be of length {key.n}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        sk = inner_product(key.msk, y)
        return _FeDDH_SK(y, sk)
