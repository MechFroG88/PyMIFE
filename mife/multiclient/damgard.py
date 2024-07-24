from typing import List, Tuple

from mife.common import discrete_log_bound, getStrongPrime

from mife.data.group import GroupBase
from mife.data.zmod import Zmod
from mife.misc.cprf import CPRF

from mife.single.damgard import _FeDamgard_MK, FeDamgard, _FeDamgard_C, _FeDamgard_SK, _FeDamgard_SK_Safe


# References:
# https://eprint.iacr.org/2019/487.pdf

class _FeDamgardMultiClient_MK:
    def __init__(self, n: int, m: int, ipfe: _FeDamgard_MK, cprf: CPRF = None):
        self.n = n
        self.m = m
        self.cprf = cprf
        self.ipfe = ipfe

    def get_enc_key(self, index: int):
        if not self.has_private_key():
            raise Exception("The master key has no private key")
        if not (0 <= index < self.n):
            raise Exception(f"Index must be within [0,{self.n})")
        return _FeDamgardMultiClient_EncK(index, self.cprf.keygen(index))

    def has_private_key(self) -> bool:
        return self.ipfe.has_private_key() and (self.cprf is not None)

    def get_public_key(self):
        return _FeDamgardMultiClient_MK(self.n, self.m, self.ipfe.get_public_key())

    def export(self):
        pass


class _FeDamgardMultiClient_EncK:
    def __init__(self, index: int, enc_key: List[bytes]):
        self.index = index
        self.enc_key = enc_key
        pass

    def export(self):
        pass


class _FeDamgardMultiClient_SK:
    def __init__(self, k: _FeDamgard_SK):
        self.k = k

    def export(self):
        pass


class _FeDamgardMultiClient_SK_Safe:
    def __init__(self, k: List[_FeDamgard_SK_Safe]):
        self.k = k

    def export(self):
        pass


class _FeDamgardMultiClient_C:
    def __init__(self, tag: bytes, c: _FeDamgard_C):
        self.c = c
        self.tag = tag

    def export(self):
        pass


class FeDamgardMultiClient:

    @staticmethod
    def generate(n: int, m: int, F: GroupBase = None) -> _FeDamgardMultiClient_MK:
        if F is None:
            F = Zmod(getStrongPrime(1024))

        cprf = CPRF(n)
        ipfe = FeDamgard.generate(n * m, F)

        return _FeDamgardMultiClient_MK(n, m, ipfe, cprf)

    @staticmethod
    def encrypt(x: List[int], tag: bytes, key: _FeDamgardMultiClient_EncK, pub: _FeDamgardMultiClient_MK) \
            -> _FeDamgardMultiClient_C:
        if len(x) != pub.m:
            raise Exception(f"Encrypt vector must be of length {pub.m}")

        length = pub.ipfe.F.order().bit_length() // 8

        tag_lst = []
        for i in range(pub.n * pub.m):
            temp = CPRF.eval(pub.n, key.index, key.enc_key, tag + f'-{i}'.encode(), length)
            tag_lst.append(temp)

        pad_x = [0 for _ in range(pub.m * key.index)] + x + [0 for _ in range(pub.m * (pub.n - key.index - 1))]

        assert len(pad_x) == len(tag_lst)
        actual_x = [i + j for i, j in zip(pad_x, tag_lst)]
        c = FeDamgard.encrypt(actual_x, pub.ipfe)

        return _FeDamgardMultiClient_C(tag, c)

    @staticmethod
    def decrypt(c: List[_FeDamgardMultiClient_C], pub: _FeDamgardMultiClient_MK,
                sk: _FeDamgardMultiClient_SK, bound: Tuple[int, int]) -> int:

        for i in range(pub.n):
            if c[i].tag != c[0].tag:
                raise Exception("All cipher text must have the same tag")

        actual_cul = pub.ipfe.F.identity()
        for k in range(pub.n):
            cul = pub.ipfe.F.identity()
            for i in range(pub.ipfe.n):
                cul = cul + sk.k.y[i] * c[k].c.c[i]
            cul = cul - sk.k.sx * c[k].c.g_r - sk.k.tx * c[k].c.h_r
            actual_cul = actual_cul + cul

        return discrete_log_bound(actual_cul, pub.ipfe.g, bound)

    @staticmethod
    def decrypt_safe(c: List[_FeDamgardMultiClient_C], pub: _FeDamgardMultiClient_MK,
                     sk: _FeDamgardMultiClient_SK_Safe, bound: Tuple[int, int]) -> int:

        for i in range(pub.n):
            if c[i].tag != c[0].tag:
                raise Exception("All cipher text must have the same tag")

        actual_cul = pub.ipfe.F.identity()
        for k in range(pub.n):
            cul = pub.ipfe.F.identity()
            for i in range(pub.ipfe.n):
                cul = cul + sk.k[k].y[i] * c[k].c.c[i]
            cul = cul - sk.k[k].g_r_sx - sk.k[k].h_r_tx
            actual_cul = actual_cul + cul

        return discrete_log_bound(actual_cul, pub.ipfe.g, bound)

    @staticmethod
    def keygen(y: List[List[int]], key: _FeDamgardMultiClient_MK) -> _FeDamgardMultiClient_SK:
        actual_y = [y[i][j] for i in range(key.n) for j in range(key.m)]
        if len(y) != key.n or len(actual_y) != key.n * key.m:
            raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
        k = FeDamgard.keygen(actual_y, key.ipfe)
        return _FeDamgardMultiClient_SK(k)

    @staticmethod
    def keygen_safe(y: List[List[int]], key: _FeDamgardMultiClient_MK, c: List[_FeDamgardMultiClient_C]):
        actual_y = [y[i][j] for i in range(key.n) for j in range(key.m)]
        if len(y) != key.n or len(actual_y) != key.n * key.m:
            raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
        k = [FeDamgard.keygen_safe(actual_y, key.ipfe, c[i].c) for i in range(key.n)]
        return _FeDamgardMultiClient_SK_Safe(k)
