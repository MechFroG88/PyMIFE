from __future__ import annotations

from secrets import randbelow
from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from typing import List, Tuple, Callable
from hashlib import shake_256

from mife.common import discrete_log_bound, inner_product, getStrongPrime
from mife.misc import cprf

from mife.data.group import GroupBase, GroupElem
from mife.data.zmod import Zmod

from mife.multiclient.rom.ddh import _FeDDHMultiClient_Hash, _FeDDHMultiClient_Hash_Default


# References:
# https://eprint.iacr.org/2019/020.pdf

def kdf(x):
    return shake_256(x).digest(16)

class _FeDDHMultiClientDec_PK:
    def __init__(self, g: GroupElem, n: int, m: int, F: GroupBase,
                 hash: _FeDDHMultiClient_Hash):
        self.g = g
        self.n = n
        self.m = m
        self.F = F
        self.hash = hash

    def generate_party(self, index: int) -> _FeDDHMultiClientDec_MK:
        if (index < 0) or (index >= self.n):
            raise Exception(f"Index must be within [0,{self.n})")

        s = [(randbelow(self.F.order()), randbelow(self.F.order())) for _ in range(self.m)]
        exc_priv_key = ECC.generate(curve='p256')

        return _FeDDHMultiClientDec_MK(self, exc_priv_key, index, s)

class _FeDDHMultiClientDec_MK:

    def __init__(self, pub: _FeDDHMultiClientDec_PK, exc_priv_key: ECC, index: int, sk: List[Tuple[int, int]]):
        self.pub = pub
        self.exc_priv_key = exc_priv_key
        self.index = index
        self.sk = sk
        self.exchange_key = [b'' for _ in range(pub.n)]
        self.share = [[] for _ in range(self.pub.n)]

    def regenerate_sk(self):
        self.sk = [(randbelow(self.pub.F.order()), randbelow(self.pub.F.order())) for _ in range(self.pub.m)]

    def get_exc_public_key(self):
        return self.exc_priv_key.public_key()

    def exchange(self, index: int, pub_key: ECC.EccKey):
        if (index < 0) or (index >= self.pub.n):
            raise Exception(f"Index must be within [0,{self.pub.n})")

        if index == self.index:
            raise Exception(f"You cannot exchange key with yourself")

        self.exchange_key[index] = key_agreement(static_priv=self.exc_priv_key, static_pub=pub_key, kdf=kdf)

    def generate_share(self, epoch=0):
        length = self.pub.F.order().bit_length() // 8
        self.share = [[] for _ in range(self.pub.n)]
        for i in range(self.pub.n):
            for j in range(self.pub.m):
                nonce = long_to_bytes(i * self.pub.m + j)
                self.share[i].append(
                    (cprf.CPRF.eval(self.pub.n, self.index, self.exchange_key,
                                    b'a' + long_to_bytes(epoch) + nonce, length) % self.pub.F.order(),
                     cprf.CPRF.eval(self.pub.n, self.index, self.exchange_key,
                                    b'b' + long_to_bytes(epoch) + nonce, length) % self.pub.F.order())
                )


class _FeDDHMultiClientDec_SK:
    def __init__(self, y: List[List[int]], d: Tuple[int, int]):
        self.y = y
        self.d = d


class _FeDDHMultiClientDec_C:
    def __init__(self, tag: bytes, c: List[GroupElem]):
        self.c = c
        self.tag = tag

class FeDDHMultiClientDec:

    @staticmethod
    def generate(n: int, m: int, F: GroupBase = None,
                 hash: Callable[[bytes, int], Tuple[int, int]] = None) -> _FeDDHMultiClientDec_PK:
        if F is None:
            F = Zmod(getStrongPrime(1024))
        if hash is None:
            hash = _FeDDHMultiClient_Hash_Default(F.order().bit_length())

        g = F.generator()

        return _FeDDHMultiClientDec_PK(g, n, m, F, hash)

    @staticmethod
    def encrypt(x: List[int], tag: bytes, key: _FeDDHMultiClientDec_MK) -> _FeDDHMultiClientDec_C:
        if len(x) != len(key.sk):
            raise Exception(f"Encrypt vector must be of length {len(key.sk)}")

        u1, u2 = key.pub.hash(tag)

        c = []

        for i in range(len(x)):
            s1, s2 = key.sk[i]
            c.append((u1 * s1 + u2 * s2 + x[i]) * key.pub.g)

        return _FeDDHMultiClientDec_C(tag, c)

    @staticmethod
    def decrypt(c: List[_FeDDHMultiClientDec_C], tag: bytes,
                key: _FeDDHMultiClientDec_PK, sk: List[_FeDDHMultiClientDec_SK],
                bound: Tuple[int, int]) -> int:

        y = sk[0].y
        d0, d1 = 0, 0
        for i in range(key.n):
            d0 += sk[i].d[0]
            d1 += sk[i].d[1]

        u1, u2 = key.hash(tag)
        u1, u2 = key.g * u1, key.g * u2

        cul = key.F.identity()

        for i in range(key.n):
            cul = cul + inner_product(c[i].c, y[i], key.F.identity())

        cul = cul - (d0 * u1 + d1 * u2)
        return discrete_log_bound(cul, key.g, bound)

    @staticmethod
    def keygen(y: List[List[int]], key: _FeDDHMultiClientDec_MK) -> _FeDDHMultiClientDec_SK:
        if len(y) != key.pub.n:
            raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
        cul_1 = 0
        cul_2 = 0

        for j in range(key.pub.m):
            s1, s2 = key.sk[j]
            cul_1 += s1 * y[key.index][j]
            cul_2 += s2 * y[key.index][j]

        for i in range(key.pub.n):
            if len(y[i]) != key.pub.m:
                raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
            for j in range(key.pub.m):
                v1, v2 = key.share[i][j]
                cul_1 += v1 * y[i][j]
                cul_2 += v2 * y[i][j]

        d = (cul_1, cul_2)
        return _FeDDHMultiClientDec_SK(y, d)
