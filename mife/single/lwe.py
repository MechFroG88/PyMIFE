import gmpy2
import random

from secrets import randbelow
from Crypto.Util.number import getPrime
from typing import List

from mife.common import inner_product
from mife.data.zmod_r import ZmodR
from mife.data.matrix import Matrix

# References:
# https://eprint.iacr.org/2015/017.pdf


class _FeLWE_MK:
    def __init__(self, p: int, q: int, l: int, n: int, m: int, delta: int, G: ZmodR,
                 A: Matrix, mpk: List[Matrix], msk: List[Matrix] = None):
        """
        Initialize FeLWE master key

        :param p: Plaintext modulus
        :param q: Ciphertext modulus
        :param l: Dimension of vector
        :param n: Dimension of the secret key
        :param m: Number of vectors to choose from in subset sum
        :param delta: round(q/p)
        :param G: Ring Z_q
        :param A: Random Matrix of size m x n
        :param mpk: [(A * s[i].T).T + e[i] for i in range(l)]
        :param msk: [Matrix([random_element_in_G for _ in range(n)]) for _ in range(l)]
        """
        self.p = p
        self.q = q
        self.l = l
        self.n = n
        self.m = m
        self.G = G
        self.A = A
        self.msk = msk
        self.mpk = mpk
        self.delta = delta

    def has_private_key(self) -> bool:
        return self.msk is not None

    def get_public_key(self):
        return _FeLWE_MK(self.p, self.q, self.l, self.n, self.m, self.delta, self.G, self.A, self.mpk)

    def export(self):
        return {
            "p": self.p,
            "q": self.q,
            "l": self.l,
            "n": self.n,
            "m": self.m,
            "delta": self.delta,
            "G": self.G.export(),
            "A": self.A.export(),
            "mpk": [x.export() for x in self.mpk],
            "msk": [x.export() for x in self.msk] if self.msk is not None else None
        }


class _FeLWE_SK:
    def __init__(self, y: List[int], sk: Matrix):
        """
        Initialize FeLWE decryption key

        :param y: Function vector
        :param sk: <msk, y>
        """
        self.y = y
        self.sk = sk

    def export(self):
        return {
            "y": self.y,
            "sk": self.sk.export()
        }

class _FeLWE_C:
    def __init__(self, a_r: Matrix, c: List[int]):
        """
        Initialize FeLWE cipher text

        :param a_r: r * A
        :param c: [<mpk[i], r> + x[i] * delta for i in range(l)]
        """
        self.a_r = a_r
        self.c = c

    def export(self):
        return {
            "a_r": self.a_r.export(),
            "c": [int(i) for i in self.c]
        }


class FeLWE:
    @staticmethod
    def generate(l: int, msg_bit: int, func_bit: int, n: int = 5) -> _FeLWE_MK:
        """
        Generate a FeLWE master key

        Parameters referred from
        https://eprint.iacr.org/2015/017.pdf
        https://github.com/fentec-project/CiFEr/blob/master/src/innerprod/simple/lwe.c

        :param l: Dimension of vector
        :param msg_bit: Upperbound of bit-size for each element in the message vector
        :param func_bit: Upperbound of bit-size for each element in the function vector
        :param n: Dimension of the secret key
        :return: FeLWE master key
        """
        p = getPrime((msg_bit + func_bit) * 2 + l.bit_length() + 1)
        q = getPrime(p.bit_length() + n.bit_length() * 2 + (msg_bit + func_bit) + l.bit_length() // 2)
        G = ZmodR(q)

        m = 2 * (l + n + 1) * q.bit_length() + 1

        delta = round(q / p)
        sigma = q / (2**func_bit * p * gmpy2.sqrt(2 * l * m * n))

        sys_random = random.SystemRandom()

        A = Matrix([[G(random.randrange(q)) for _ in range(n)] for _ in range(m)])
        s = [Matrix([G(randbelow(q)) for _ in range(n)]) for _ in range(l)]
        e = [Matrix([G(round(sys_random.gauss(0, sigma))) for _ in range(m)]) for _ in range(l)]

        mpk = [(A * s[i].T).T + e[i] for i in range(l)]

        return _FeLWE_MK(p=p, q=q, l=l, n=n, m=m, A=A, G=G, delta=delta, mpk=mpk, msk=s)

    @staticmethod
    def encrypt(x: List[int], pub: _FeLWE_MK) -> _FeLWE_C:
        """
        Encrypt FeLWE message vector

        :param x: Message vector
        :param pub: FeLWE public key
        :return: FeLWE cipher text
        """
        if len(x) != pub.l:
            raise Exception("Encrypt vector must be of length l")

        c = []

        r = Matrix([pub.G(randbelow(2)) for _ in range(pub.m)])
        a_r = r * pub.A

        for i in range(pub.l):
            c.append(pub.mpk[i].dot(r) + x[i] * pub.delta)

        return _FeLWE_C(a_r, c)

    @staticmethod
    def decrypt(c: _FeLWE_C, pub: _FeLWE_MK, sk: _FeLWE_SK) -> int:
        """
        Decrypt FeLWE cipher text

        :param c: FeLWE cipher text
        :param pub: FeLWE public key
        :param sk: FeLWE decryption key
        :return: Decrypted message
        """
        cul = pub.G(0)
        for i in range(pub.l):
            cul = cul + sk.y[i] * c.c[i]
        cul = cul - sk.sk.dot(c.a_r)
        t = int(cul)
        if t > pub.q//2:
            t = -(pub.q - t)
        return round(t / pub.delta)

    @staticmethod
    def keygen(y: List[int], key: _FeLWE_MK) -> _FeLWE_SK:
        """
        Generate FeLWE decryption key

        :param y: Function vector
        :param key: FeLWE master key
        :return: FeLWE decryption key
        """
        if len(y) != key.l:
            raise Exception(f"Function vector must be of length {key.l}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        sk = inner_product(key.msk, y, identity=Matrix([0 for _ in range(key.n)]))
        return _FeLWE_SK(y, sk)
