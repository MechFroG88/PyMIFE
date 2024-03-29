from secrets import randbelow
from typing import List, Tuple, Any

from mife.common import discrete_log_bound, invertible_matrix, discrete_log_bound_brute
from mife.data.pairing import PairingBase
from mife.data.pyecc_bn128_wrapper import Bn128Pairing
from mife.data.matrix import Matrix
from mife.data.group import GroupElem
from mife.data.zmod_r import ZmodR


# References:
# https://eprint.iacr.org/2016/440.pdf

class _FeDDH_MSK:
    def __init__(self,  g1: GroupElem, g2: GroupElem, B: Matrix, B_star: Matrix, B_determinant: Any):
        self.g1 = g1
        self.g2 = g2
        self.B = B
        self.B_star = B_star
        self.B_determinant = B_determinant

class _FeDDH_MK:
    def __init__(self, n: int, F: PairingBase, G: ZmodR, msk: _FeDDH_MSK = None):
        self.n = n
        self.F = F
        self.G = G
        self.msk = msk

    def has_private_key(self) -> bool:
        return self.msk is not None

    def get_public_key(self):
        return _FeDDH_MK(self.n, self.F, self.G)


class _FeDDH_SK:
    def __init__(self, k1: GroupElem, k2: List[GroupElem]):
        self.k1 = k1
        self.k2 = k2

class _FeDDH_C:
    def __init__(self, c1: GroupElem, c2: List[GroupElem]):
        self.c1 = c1
        self.c2 = c2

class FeDDH:

    @staticmethod
    def generate(n: int, F: PairingBase = None) -> _FeDDH_MK:
        """
        Generate a FeDDH master key

        :param n: Dimension of the encrypt vector
        :param F: Group to use for the scheme. If set to None, bn128 will be used
        :return: FeDDH master key
        """
        if F is None:
            F = Bn128Pairing()
        g1 = F.generator1()
        g2 = F.generator2()

        G = ZmodR(F.order())
        B = invertible_matrix(G, n)
        B_determinant = B.determinant()
        B_star = int(B_determinant) * B.inverse().T

        msk = _FeDDH_MSK(g1, g2, B, B_star, B_determinant)

        return _FeDDH_MK(n, F, G, msk=msk)

    @staticmethod
    def encrypt(x: List[int], key: _FeDDH_MK) -> _FeDDH_C:
        """
        Encrypt FeDDH message vector

        :param x: Message vector
        :param key: FeDDH master key
        :return: FeDDH cipher text
        """
        if len(x) != key.n:
            raise Exception(f"Encrypt vector must be of length {key.n}")

        beta = randbelow(key.G.order())

        c1 = beta * key.msk.g2

        x = [key.G(x[i]) for i in range(key.n)]
        exponents = Matrix.flatten((Matrix(x) * key.msk.B_star).M)
        c2 = [int(exponents[i] * beta) * key.msk.g2 for i in range(key.n)]

        return _FeDDH_C(c1, c2)

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
        d1 = pub.F.pairing(sk.k1, c.c1)

        d2 = pub.F.pairing(sk.k2[0], c.c2[0])
        for i in range(1, pub.n):
            d2 = d2 + pub.F.pairing(sk.k2[i], c.c2[i])

        return discrete_log_bound(d2, d1, bound)


    @staticmethod
    def keygen(y: List[int], key: _FeDDH_MK) -> _FeDDH_SK:
        """
        Generate FeDDH decryption key

        :param y: Function vector
        :param key: FeDDH master key
        :return: FeDDH decryption key
        """
        if len(y) != key.n:
            raise Exception(f"Function vector must be of length {key.n}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")

        alpha = randbelow(key.G.order())

        k1 = (int(alpha * key.msk.B_determinant)) * key.msk.g1

        y = [key.G(y[i]) for i in range(key.n)]
        exponents = Matrix.flatten((Matrix(y) * key.msk.B).M)
        k2 = [int(exponents[i] * alpha) * key.msk.g1 for i in range(key.n)]

        return _FeDDH_SK(k1, k2)
