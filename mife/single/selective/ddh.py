from secrets import randbelow
from typing import List, Tuple

from mife.common import inner_product, discrete_log_bound, getStrongPrime
from mife.data.zmod import Zmod
from mife.data.group import GroupBase, GroupElem

# References:
# https://eprint.iacr.org/2015/017.pdf

class _FeDDH_MK:
    def __init__(self, g: GroupElem, n: int, F: GroupBase, mpk: List[GroupElem], msk: List[int]=None):
        """
        Initialize FeDDH master key

        :param g: Generator of the group
        :param n: Dimension of the vector
        :param F: The Group
        :param mpk: Master public key
        :param msk: Master secret key
        """
        self.g = g
        self.n = n
        self.F = F
        self.msk = msk
        self.mpk = mpk

    def has_private_key(self) -> bool:
        return self.msk is not None

    def get_public_key(self):
        return _FeDDH_MK(self.g, self.n, self.F, self.mpk)

    def export(self):
        return {
            "g": self.g.export(),
            "n": self.n,
            "F": self.F.export(),
            "mpk": [x.export() for x in self.mpk],
            "msk": self.msk
        }


class _FeDDH_SK:
    def __init__(self, y: List[int], sk: int):
        """
        Initialize FeDDH decryption key

        :param y: function vector
        :param sk: <msk, y>
        """
        self.y = y
        self.sk = sk

    def export(self):
        return {
            "y": self.y,
            "sk": self.sk
        }

class _FeDDH_C:
    def __init__(self, g_r: GroupElem, c: List[GroupElem]):
        """
        Initialize FeDDH cipher text

        :param g_r: r * g
        :param c: x[i] * g + r * mpk[i]
        """
        self.g_r = g_r
        self.c = c

    def export(self):
        return {
            "g_r": self.g_r.export(),
            "c": [x.export() for x in self.c]
        }


class FeDDH:
    @staticmethod
    def generate(n: int, F: GroupBase = None) -> _FeDDH_MK:
        """
        Generate a FeDDH master key

        :param n: Dimension of the encrypt vector
        :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
        :return: FeDDH master key
        """
        if F is None:
            F = Zmod(getStrongPrime(1024))
        g = F.generator()
        msk = [randbelow(F.order()) for _ in range(n)]
        mpk = [msk[i] * g for i in range(n)]

        return _FeDDH_MK(g, n, F, msk=msk, mpk=mpk)

    @staticmethod
    def encrypt(x: List[int], pub: _FeDDH_MK) -> _FeDDH_C:
        """
        Encrypt message vector

        :param x: Message vector
        :param pub: FeDDH public key
        :return: FeDDH cipher text
        """
        if len(x) != pub.n:
            raise Exception("Encrypt vector must be of length n")
        r = randbelow(pub.F.order())
        g_r = r * pub.g
        c = [r * pub.mpk[i] + x[i] * pub.g for i in range(pub.n)]
        return _FeDDH_C(g_r, c)

    @staticmethod
    def decrypt(c: _FeDDH_C, pub: _FeDDH_MK, sk: _FeDDH_SK, bound: Tuple[int, int]) -> int:
        """
        Decrypt FeDDH cipher text within a bound

        :param c: FeDDH cipher text
        :param pub: FeDDH public key
        :param sk: FeDDH decryption key
        :param bound: Bound for discrete logarithm search, the decrypted text should be within the bound
        :return: Decrypted message
        """
        cul = pub.F.identity()
        for i in range(pub.n):
            cul = cul + sk.y[i] * c.c[i]
        cul = cul - sk.sk * c.g_r
        return discrete_log_bound(cul, pub.g, bound)

    @staticmethod
    def keygen(y: List[int], key: _FeDDH_MK) -> _FeDDH_SK:
        """
        Generate a FeDDH decryption key

        :param y: Function vector
        :param key: FeDDH master key
        :return: FeDDH decryption key
        """
        if len(y) != key.n:
            raise Exception(f"Function vector must be of length {key.n}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        sk = inner_product(key.msk, y) % key.F.order()
        return _FeDDH_SK(y, sk)
