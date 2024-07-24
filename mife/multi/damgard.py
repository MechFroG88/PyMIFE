from secrets import randbelow
from typing import List, Tuple

from mife.data.matrix import Matrix
from mife.common import discrete_log_bound, inner_product, getStrongPrime
from mife.data.group import GroupBase, GroupElem
from mife.data.zmod import Zmod

# References:
# https://eprint.iacr.org/2017/972.pdf


class _FeDamgardMulti_MPK:

    def __init__(self, a: Matrix, wa: Matrix):
        """
        Initialize FeDamgardMulti master public key

        :param a: [1, random_element]
        :param wa: W * a
        """
        self.a = a
        self.wa = wa

    def export(self):
        return {
            "a": self.a.export(),
            "wa": self.wa.export()
        }


class _FeDamgardMulti_MSK:

    def __init__(self, w: Matrix, u: Matrix):
        """
        Initialize FeDamgardMulti master secret key

        :param w: [[random_element, random_element] for _ in range(m)]]
        :param u: [[random_element for _ in range(m)] for _ in range(n)]]
        """
        self.w = w
        self.u = u

    def export(self):
        return {
            "w": self.w.export(),
            "u": self.u.export()
        }

class _FeDamgardMulti_EncK:
    def __init__(self, g: GroupElem, F: GroupBase, mpk: _FeDamgardMulti_MPK, u: Matrix):
        """
        Initialize FeDamgardMulti encryption key

        :param g: Generator of the group
        :param F: Group to use for the scheme
        :param mpk: Master public key
        :param u: Some row of the original u matrix
        """
        self.g = g
        self.F = F
        self.mpk = mpk
        self.u = u

    def export(self):
        return {
            "g": self.g.export(),
            "F": self.F.export(),
            "mpk": self.mpk.export(),
            "u": self.u.export()
        }



class _FeDamgardMulti_MK:
    def __init__(self, g: GroupElem, n: int, m: int, F: GroupBase,
                 mpk: _FeDamgardMulti_MPK, msk: _FeDamgardMulti_MSK = None):
        """
        Initialize FeDamgardMulti master key

        :param g: Generator of the group
        :param n: Number of vector positions
        :param m: Dimension of the vector in each input
        :param F: Group to use for the scheme
        :param mpk: Master public key
        :param msk: Master secret key
        """
        self.g = g
        self.n = n
        self.m = m
        self.F = F
        self.to_group = lambda x: x * self.g
        self.msk = msk
        self.mpk = mpk

    def get_enc_key(self, index: int):
        """
        Get the encryption key for a client

        :param index: Index of the client
        :return: Encryption key for the client
        """
        if not self.has_private_key:
            raise Exception("The master key has no private key")
        if not (0 <= index < self.n):
            raise Exception(f"Index must be within [0,{self.n})")
        return _FeDamgardMulti_EncK(self.g, self.F, self.mpk, self.msk.u.row(index))

    def has_private_key(self) -> bool:
        return self.msk is not None

    def get_public_key(self):
        return _FeDamgardMulti_MK(self.g, self.n, self.m, self.F, self.mpk)

    def export(self):
        return {
            "g": self.g.export(),
            "n": self.n,
            "m": self.m,
            "F": self.F.export(),
            "mpk": self.mpk.export(),
            "msk": self.msk.export() if self.msk is not None else None
        }


class _FeDamgardMulti_SK:
    def __init__(self, y: List[List[int]], d: List[Matrix], z: int):
        """
        Initialize FeDamgardMulti decryption key

        :param y: Function vector
        :param d: [y[i] * w for i in range(n)]
        :param z: <u, y>
        """
        self.y = y
        self.d = d
        self.z = z

    def export(self):
        return {
            "y": [[int(i) for i in vec] for vec in self.y],
            "d": [x.export() for x in self.d],
            "z": self.z
        }


class _FeDamgardMulti_C:
    def __init__(self, t: Matrix, c: Matrix):
        """
        Initialize FeDamgardMulti cipher text

        :param t:  r * a
        :param c: [(x[i] + u[i]) * g] + r * wa
        """
        self.t = t
        self.c = c

    def export(self):
        return {
            "t": self.t.export(),
            "c": self.c.export()
        }


class FeDamgardMulti:
    @staticmethod
    def generate(n: int, m: int, F: GroupBase = None) -> _FeDamgardMulti_MK:
        """
        Generate a FeDamgardMulti master key

        :param n: Number of vector positions
        :param m: Dimension of the vector in each input
        :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
        :return: FeDamgardMulti master key
        """
        if F is None:
            F = Zmod(getStrongPrime(1024))
        g = F.generator()
        a_v = Matrix([1, randbelow(F.order())])
        W = Matrix([[randbelow(F.order()), randbelow(F.order())] for _ in range(m)])
        u = Matrix([[randbelow(F.order()) for _ in range(m)] for _ in range(n)])

        to_group = lambda x: x * g

        msk = _FeDamgardMulti_MSK(W, u)
        mpk = _FeDamgardMulti_MPK(a_v.apply_func(to_group), (W * a_v.T).apply_func(to_group))

        return _FeDamgardMulti_MK(g, n, m, F, msk=msk, mpk=mpk)

    @staticmethod
    def encrypt(x: List[int], key: _FeDamgardMulti_EncK) -> _FeDamgardMulti_C:
        """
        Encrypt a message vector

        :param x: Message vector (Dimension must be m)
        :param key: FeDamgardMulti public key
        :return: FeDamgardMulti cipher text
        """
        x = Matrix(x)
        r = randbelow(key.F.order())

        t = r * key.mpk.a

        c = (x + key.u).apply_func(lambda x: x * key.g) + (r * key.mpk.wa).T

        return _FeDamgardMulti_C(t, c)

    @staticmethod
    def decrypt(c: List[_FeDamgardMulti_C], key: _FeDamgardMulti_MK, sk: _FeDamgardMulti_SK,
                bound: Tuple[int, int]) -> int:
        """
        Decrypt a message vector

        :param c: FeDamgardMulti cipher text
        :param key: FeDamgardMulti public key
        :param sk: FeDamgardMulti decryption key
        :param bound: Bound for the discrete log problem
        :return: Decrypted message vector
        """
        cul = key.F.identity()
        for i in range(key.n):
            # [y_i dot c_i]
            yc = inner_product(sk.y[i], c[i].c[0], identity=key.F.identity())

            # [d_i dot t_i]
            dt = inner_product(sk.d[i][0], c[i].t[0], identity=key.F.identity())

            cul = cul + yc - dt

        cul = cul - key.to_group(sk.z)
        return discrete_log_bound(cul, key.g, bound)

    @staticmethod
    def keygen(y: List[List[int]], key: _FeDamgardMulti_MK) -> _FeDamgardMulti_SK:
        """
        Generate a FeDamgardMulti decryption key

        :param y: Function vector (n x m matrix)
        :param key: FeDamgardMulti master key
        :return: FeDamgardMulti decryption key
        """
        if len(y) != key.n:
            raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
        d = []
        z = 0
        for i in range(key.n):
            if len(y[i]) != key.m:
                raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
            y_i = Matrix(y[i])
            d.append(y_i * key.msk.w)
            z += y_i.dot(key.msk.u.row(i))

        return _FeDamgardMulti_SK(y, d, z)
