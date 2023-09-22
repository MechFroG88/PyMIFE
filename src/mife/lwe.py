import gmpy2
import math
import random

from secrets import randbits, randbelow
from Crypto.Util.number import getPrime, inverse
from typing import List, Tuple

from src.mife.common import inner_product, discrete_log_bound
from src.mife.data.zmod_r import ZmodR
from src.mife.data.matrix import Matrix

# https://eprint.iacr.org/2015/017.pdf


class _FeLWE_MK:
    def __init__(self, p: int, q: int, l: int, n: int, m: int, delta: int, G: ZmodR,
                 A: Matrix, mpk: List[Matrix], msk: List[Matrix] = None):
        self.p = p
        self.q = q
        self.l = l
        self.n = n
        self.m = m
        self.delta = delta
        self.G = G
        self.A = A
        self.msk = msk
        self.mpk = mpk

    def has_private_key(self) -> bool:
        return self.msk is not None


class _FeLWE_SK:
    def __init__(self, y: List[int], sk: Matrix):
        self.y = y
        self.sk = sk

class _FeLWE_C:
    def __init__(self, a_r: Matrix, c: List[int]):
        self.a_r = a_r
        self.c = c


class FeLWE:
    @staticmethod
    def generate(l: int, msg_bit: int, func_bit: int, n: int = 5) -> _FeLWE_MK:

        p = getPrime((msg_bit + func_bit) * 2 + l.bit_length() + 1)
        q = getPrime(p.bit_length() + n.bit_length() * 2 + (msg_bit + func_bit) + l.bit_length() // 2)
        G = ZmodR(q)

        m = 2 * (l + n + 1) * q.bit_length() + 1
        delta = round(q / p)
        sigma = delta / (2**func_bit * gmpy2.sqrt(2 * l * m * n))
        sys_random = random.SystemRandom()

        A = Matrix([[G(random.randrange(q)) for _ in range(n)] for _ in range(m)])
        s = [Matrix([G(randbelow(q)) for _ in range(n)]) for _ in range(l)]
        e = [Matrix([G(round(sys_random.gauss(0, sigma))) for _ in range(m)]) for _ in range(l)]

        mpk = [(A * s[i].T).T + e[i] for i in range(l)]

        return _FeLWE_MK(p=p, q=q, l=l, n=n, m=m, A=A, G=G, delta=delta, mpk=mpk, msk=s)

    @staticmethod
    def encrypt(x: List[int], pub: _FeLWE_MK) -> _FeLWE_C:
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
        if len(y) != key.l:
            raise Exception(f"Function vector must be of length {key.l}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        sk = inner_product(key.msk, y, identity=Matrix([0 for _ in range(key.n)]))
        return _FeLWE_SK(y, sk)
