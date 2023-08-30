from secrets import randbits, randbelow
from Crypto.Util.number import getStrongPrime, inverse
from typing import List, Tuple

from src.mife.common import pow, inner_product, discrete_log_bound

# https://eprint.iacr.org/2015/608.pdf

class _FeDamgard_MK:
    def __init__(self, g: int, h: int, n: int, p: int, **kwargs):
        self.g = g
        self.h = h
        self.n = n
        self.p = p
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
    def __init__(self, g_r: int, h_r: int, c: List[int]):
        self.g_r = g_r
        self.h_r = h_r
        self.c = c


class FeDamgard:
    @staticmethod
    def generate(n: int, bits: int) -> _FeDamgard_MK:
        g = 2
        h = 3
        p = getStrongPrime(bits)
        msk = [(randbits(bits), randbits(bits)) for _ in range(n)]
        mpk = [(pow(g, msk[i][0], p) * pow(h, msk[i][1], p)) % p for i in range(n)]
        return _FeDamgard_MK(g, h, n, p, msk=msk, mpk=mpk)

    @staticmethod
    def encrypt(x: List[int], pub: _FeDamgard_MK) -> _FeDamgard_C:
        if len(x) != pub.n:
            raise Exception(f"Encrypt vector must be of length {pub.n}")
        r = randbelow(pub.p)
        g_r = pow(pub.g, r, pub.p)
        h_r = pow(pub.h, r, pub.p)
        c = [(pow(pub.mpk[i], r, pub.p) * pow(pub.g, x[i], pub.p)) % pub.p for i in range(pub.n)]
        return _FeDamgard_C(g_r, h_r, c)

    @staticmethod
    def decrypt(c: _FeDamgard_C, pub: _FeDamgard_MK, sk: _FeDamgard_SK, bound: Tuple[int, int]) -> int:
        cul = 1
        for i in range(pub.n):
            cul = (cul * pow(c.c[i], sk.y[i], pub.p)) % pub.p
        cul = (cul * inverse(pow(c.g_r, sk.sx, pub.p), pub.p)) % pub.p
        cul = (cul * inverse(pow(c.h_r, sk.tx, pub.p), pub.p)) % pub.p
        return discrete_log_bound(pub.p, cul, pub.g, bound)

    @staticmethod
    def keygen(y: List[int], key: _FeDamgard_MK) -> _FeDamgard_SK:
        if len(y) != key.n:
            raise Exception(f"Function vector must be of length {key.n}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        sx = inner_product([key.msk[i][0] for i in range(key.n)], y)
        tx = inner_product([key.msk[i][1] for i in range(key.n)], y)
        return _FeDamgard_SK(y, sx, tx)
