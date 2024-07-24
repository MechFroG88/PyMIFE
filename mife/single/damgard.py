from secrets import randbelow
from typing import List, Tuple

from mife.common import inner_product, discrete_log_bound, getStrongPrime
from mife.data.zmod import Zmod
from mife.data.group import GroupBase, GroupElem

# References:
# https://eprint.iacr.org/2015/608.pdf

class _FeDamgard_MK:
    def __init__(self, g: GroupElem, h: GroupElem, n: int, F: GroupBase,
                 mpk: List[GroupElem], msk: List[Tuple[int, int]] = None):
        """
        Initialize FeDamgard master key

        :param g: First generator of the group
        :param h: Second generator of the group
        :param n: Dimension of the vector
        :param F: Group to use for the scheme.
        :param mpk: Master public key
        :param msk: Master secret key
        """
        self.g = g
        self.h = h
        self.n = n
        self.F = F
        self.msk = msk
        self.mpk = mpk

    def has_private_key(self) -> bool:
        return self.msk is not None

    def get_public_key(self):
        return _FeDamgard_MK(self.g, self.h, self.n, self.F, self.mpk)

    def export(self):
        return {
            "g": self.g.export(),
            "h": self.h.export(),
            "n": self.n,
            "F": self.F.export(),
            "mpk": [x.export() for x in self.mpk],
            "msk": self.msk
        }

class _FeDamgard_SK:
    def __init__(self, y: List[int], sx: int, tx: int):
        """
        Initialize FeDamgard decryption key

        :param y: Function vector
        :param sx: <s, y>
        :param tx: <t, y>
        """
        self.y = y
        self.sx = sx
        self.tx = tx

    def export(self):
        return {
            "y": self.y,
            "sx": self.sx,
            "tx": self.tx
        }

class _FeDamgard_SK_Safe:
    def __init__(self, y: List[int], g_r_sx: GroupElem, h_r_tx: GroupElem):
        """
        Initialize FeDamgard decryption key

        :param y: Function vector
        :param g_r_sx: g * (r + <s, y>)
        :param h_r_tx: h * (r + <t, y>)
        """
        self.y = y
        self.g_r_sx = g_r_sx
        self.h_r_tx = h_r_tx

    def export(self):
        return {
            "y": self.y,
            "g_r_sx": self.g_r_sx,
            "h_r_tx": self.h_r_tx
        }



class _FeDamgard_C:
    def __init__(self, g_r: GroupElem, h_r: GroupElem, c: List[GroupElem]):
        """
        Initialize FeDamgard cipher text

        :param g_r: r * g
        :param h_r: r * h
        :param c: x[i] * g + r * mpk[i]
        """
        self.g_r = g_r
        self.h_r = h_r
        self.c = c

    def export(self):
        return {
            "g_r": self.g_r.export(),
            "h_r": self.h_r.export(),
            "c": [x.export() for x in self.c]
        }


class FeDamgard:

    @staticmethod
    def generate(n: int, F: GroupBase = None) -> _FeDamgard_MK:
        """
        Generate a FeDamgard master key

        :param n: Dimension of the encrypt vector
        :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
        :return: FeDamgard master key
        """
        if F is None:
            F = Zmod(getStrongPrime(1024))
        for _ in range(100):
            g = F.generator()
            h = F.generator()
            if g != h:
                break
        if g == h:
            print(f"There must be at least 2 distinct generator for the Group {F}")
        msk = [(randbelow(F.order()), randbelow(F.order())) for _ in range(n)]
        mpk = [msk[i][0] * g + msk[i][1] * h for i in range(n)]
        return _FeDamgard_MK(g, h, n, F, msk=msk, mpk=mpk)

    @staticmethod
    def encrypt(x: List[int], pub: _FeDamgard_MK) -> _FeDamgard_C:
        """
        Encrypt FeDamgard message vector

        :param x: Message vector
        :param pub: FeDamgard public key
        :return: FeDamgard cipher text
        """
        if len(x) != pub.n:
            raise Exception(f"Encrypt vector must be of length {pub.n}")
        r = randbelow(pub.F.order())
        g_r = r * pub.g
        h_r = r * pub.h
        c = [r * pub.mpk[i] + x[i] * pub.g for i in range(pub.n)]
        return _FeDamgard_C(g_r, h_r, c)

    @staticmethod
    def decrypt(c: _FeDamgard_C, pub: _FeDamgard_MK, sk: _FeDamgard_SK, bound: Tuple[int, int]) -> int:
        """
        Decrypt FeDamgard cipher text within a bound

        :param c: FeDamgard cipher text
        :param pub: FeDamgard public key
        :param sk: FeDamgard decryption key
        :param bound: Bound for discrete logarithm search, the decrypted text should be within the bound
        :return: Decrypted message
        """
        cul = pub.F.identity()
        for i in range(pub.n):
            cul = cul + sk.y[i] * c.c[i]
        cul = cul - sk.sx * c.g_r - sk.tx * c.h_r
        return discrete_log_bound(cul, pub.g, bound)

    @staticmethod
    def decrypt_safe(c: _FeDamgard_C, pub: _FeDamgard_MK, sk: _FeDamgard_SK_Safe, bound: Tuple[int, int]):
        """
        Decrypt FeDamgard cipher text within a bound using safe key

        :param c: FeDamgard cipher text
        :param pub: FeDamgard public key
        :param sk: FeDamgard decryption key
        :param bound: Bound for discrete logarithm search, the decrypted text should be within the bound
        :return: Decrypted message
        """
        cul = pub.F.identity()
        for i in range(pub.n):
            cul = cul + sk.y[i] * c.c[i]
        cul = cul - sk.g_r_sx - sk.h_r_tx
        return discrete_log_bound(cul, pub.g, bound)


    @staticmethod
    def keygen(y: List[int], key: _FeDamgard_MK) -> _FeDamgard_SK:
        """
        Generate FeDamgard decryption key

        :param y: Function vector
        :param key: FeDamgard master key
        :return: FeDamgard decryption key
        """
        if len(y) != key.n:
            raise Exception(f"Function vector must be of length {key.n}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        sx = inner_product([key.msk[i][0] for i in range(key.n)], y) % key.F.order()
        tx = inner_product([key.msk[i][1] for i in range(key.n)], y) % key.F.order()
        return _FeDamgard_SK(y, sx, tx)

    @staticmethod
    def keygen_safe(y: List[int], key: _FeDamgard_MK, c: _FeDamgard_C) -> _FeDamgard_SK_Safe:
        """
        Generate FeDamgard safer decryption key

        :param y: Function vector
        :param key: FeDamgard
        :param c: FeDamgard cipher text
        :return: FeDamgard decryption key
        """
        normal_key = FeDamgard.keygen(y, key)
        g_r_sx = c.g_r * normal_key.sx
        h_r_tx = c.h_r * normal_key.tx
        return _FeDamgard_SK_Safe(y, g_r_sx, h_r_tx)


