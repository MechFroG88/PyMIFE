from secrets import randbelow
from typing import List, Tuple

from mife.common import discrete_log_bound, invertible_matrix
from mife.data.pairing import PairingBase
from mife.data.pyecc_bn128_wrapper import Bn128Pairing
from mife.data.matrix import Matrix
from mife.data.group import GroupElem
from mife.data.zmod_r import ZmodR, _ZmodRElem


# References:
# https://eprint.iacr.org/2018/206.pdf

class _FeDDH_MSK:
    def __init__(self, s: List[_ZmodRElem], t: List[_ZmodRElem]):
        self.s = s
        self.t = t

class _FeDDH_MK:
    def __init__(self, n: int, F: PairingBase, G: ZmodR, gs: List[GroupElem], gt: List[GroupElem], msk: _FeDDH_MSK = None):
        self.n = n
        self.F = F
        self.G = G
        self.gs = gs
        self.gt = gt
        self.msk = msk

    def has_private_key(self) -> bool:
        return self.msk is not None

    def get_public_key(self):
        return _FeDDH_MK(self.n, self.F, self.G, self.gs, self.gt)


class _FeDDH_SK:
    def __init__(self, g2f: GroupElem, f: List[List[int]]):
        self.g2f = g2f
        self.f = f

class _FeDDH_C:
    def __init__(self, g1_gamma: GroupElem, c: List[List[GroupElem]]):
        self.g1_gamma = g1_gamma
        self.c = c

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

        G = ZmodR(F.order())

        s = [G(randbelow(F.order())) for i in range(n)]
        t = [G(randbelow(F.order())) for i in range(n)]

        g1 = F.generator1()
        g2 = F.generator2()

        gs = [int(s[i]) * g1 for i in range(n)]
        gt = [int(t[i]) * g2 for i in range(n)]

        msk = _FeDDH_MSK(s,t)

        return _FeDDH_MK(n, F, G, gs, gt, msk=msk)

    @staticmethod
    def encrypt(x: List[int], y: List[int], key: _FeDDH_MK) -> _FeDDH_C:
        """
        Encrypt FeDDH message vector

        :param x: First Message vector
        :param y: Second Message vector
        :param key: FeDDH master key
        :return: FeDDH cipher text
        """
        if len(x) != key.n or len(y) != key.n:
            raise Exception(f"Encrypt vector must be of length {key.n}")

        gamma = randbelow(key.G.order())
        W = invertible_matrix(key.G, 2)
        W_iT = W.inverse().T

        c = [[] for i in range(key.n)]

        g1 = key.F.generator1()
        g2 = key.F.generator2()

        for i in range(key.n):
            a = Matrix.flatten((W_iT * Matrix([x[i], gamma * key.msk.s[i]]).T).M)
            b = Matrix.flatten((W * Matrix([y[i], -key.msk.t[i]]).T).M)
            c[i] = [int(a[0]) * g1, int(a[1]) * g1, int(b[0]) * g2, int(b[1]) * g2]

        return _FeDDH_C(gamma * g1, c)

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
        out = pub.F.pairing(c.g1_gamma, sk.g2f)

        for i in range(pub.n):
            for j in range(pub.n):
                t = pub.F.pairing(c.c[i][0], c.c[j][2]) + pub.F.pairing(c.c[i][1], c.c[j][3])
                out += sk.f[i][j] * t

        g1 = pub.F.generator1()
        g2 = pub.F.generator2()

        return discrete_log_bound(out, pub.F.pairing(g1, g2), bound)


    @staticmethod
    def keygen(f: List[List[int]], key: _FeDDH_MK) -> _FeDDH_SK:
        """
        Generate FeDDH decryption key

        :param f: Function vector f[i][j] is the coefficient for x_iy_j
        :param key: FeDDH master key
        :return: FeDDH decryption key
        """
        if len(f) != key.n:
            raise Exception(f"Function vector must be of shape {key.n} x {key.n}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")

        eval = 0

        for i in range(key.n):
            if len(f[i]) != key.n:
                raise Exception(f"Function vector must be of shape {key.n} x {key.n}")
            for j in range(key.n):
                eval += f[i][j] * key.msk.s[i] * key.msk.t[j]

        g2f = int(eval) * key.F.generator2()

        return _FeDDH_SK(g2f, f)
