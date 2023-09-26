from secrets import randbelow
from Crypto.Util.number import getStrongPrime, bytes_to_long
from typing import List, Tuple, Callable

from src.mife.data.matrix import Matrix
from src.mife.common import discrete_log_bound, inner_product

from src.mife.data.group import GroupBase, GroupElem
from src.mife.data.zmod import Zmod

from hashlib import shake_256


# https://eprint.iacr.org/2017/989.pdf

class _FeDDHMultiClient_MK:
    def __init__(self, g: GroupElem, n: int, m: int, F: GroupBase,
                 hash: Callable[[bytes], Tuple[int, int]],
                 msk: List[List[Tuple[int, int]]] = None):
        self.g = g
        self.n = n
        self.m = m
        self.F = F
        self.hash = hash
        self.msk = msk

    def get_enc_key(self, index: int):
        if not self.has_private_key:
            raise Exception("The master key has no private key")
        if not (0 <= index < self.n):
            raise Exception(f"Index must be within [0,{self.n})")
        return _FeDDHMultiClient_EncK(self.g, self.hash, self.msk[index])

    def has_private_key(self) -> bool:
        return self.msk is not None

class _FeDDHMultiClient_EncK:
    def __init__(self, g: GroupElem,
                 hash: Callable[[bytes], Tuple[int, int]],
                 enc_key: List[Tuple[int, int]]):
        self.g = g
        self.hash = hash
        self.enc_key = enc_key


class _FeDDHMultiClient_SK:
    def __init__(self, y: List[List[int]], d: Tuple[int, int]):
        self.y = y
        self.d = d

class _FeDDHMultiClient_C:
    def __init__(self, c: List[GroupElem]):
        self.c = c

class FeDDHMultiClient:

    @staticmethod
    def default_hash(tag : bytes, maximum_bit: int) -> Tuple[int, int]:
        t = shake_256(tag).digest(maximum_bit * 2)
        return bytes_to_long(t[:len(t)//2]), bytes_to_long(t[len(t)//2:])

    @staticmethod
    def generate(n: int, m: int, F: GroupBase = None,
                 hash: Callable[[bytes, int], Tuple[int, int]] = None) -> _FeDDHMultiClient_MK:
        if F is None:
            F = Zmod(getStrongPrime(1024))
        if hash is None:
            hash = lambda x: FeDDHMultiClient.default_hash(x, F.order().bit_length())

        g = F.generator()
        s = [[(randbelow(F.order()), randbelow(F.order())) for _ in range(m)] for _ in range(n)]

        return _FeDDHMultiClient_MK(g, n, m, F, hash, msk=s)

    @staticmethod
    def encrypt(x: List[int], tag: bytes, key: _FeDDHMultiClient_EncK) -> _FeDDHMultiClient_C:
        if len(x) != len(key.enc_key):
            raise Exception(f"Encrypt vector must be of length {len(key.enc_key)}")

        u1, u2 = key.hash(tag)

        c = []

        for i in range(len(x)):
            s1, s2 = key.enc_key[i]
            c.append((u1 * s1 + u2 * s2 + x[i]) * key.g)

        return _FeDDHMultiClient_C(c)

    @staticmethod
    def decrypt(c: List[_FeDDHMultiClient_C], tag: bytes,
                key: _FeDDHMultiClient_MK, sk: _FeDDHMultiClient_SK,
                bound: Tuple[int, int]) -> int:
        u1, u2 = key.hash(tag)
        u1, u2 = key.g * u1, key.g * u2

        cul = key.F.identity()

        for i in range(key.n):
            cul = cul + inner_product(c[i].c, sk.y[i], key.F.identity())

        cul = cul - (sk.d[0] * u1 + sk.d[1] * u2)
        return discrete_log_bound(cul, key.g, bound)

    @staticmethod
    def keygen(y: List[List[int]], key: _FeDDHMultiClient_MK) -> _FeDDHMultiClient_SK:
        if len(y) != key.n:
            raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
        cul_1 = 0
        cul_2 = 0
        for i in range(key.n):
            if len(y[i]) != key.m:
                raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
            for j in range(key.m):
                s1, s2 = key.msk[i][j]
                cul_1 += s1 * y[i][j]
                cul_2 += s2 * y[i][j]

        d = (cul_1, cul_2)
        return _FeDDHMultiClient_SK(y, d)
