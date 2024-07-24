import math

import random

from secrets import randbelow
from Crypto.Util.number import getPrime
from typing import List

from numpy import array as Matrix

# References:
# https://eprint.iacr.org/2015/608.pdf


class _FeLWE_MK:
    def __init__(self, l: int, msg_bit: int, func_bit: int, k: int, n: int, m: int, q: int, U: Matrix, A: Matrix,
                 alpha: float, Z: Matrix = None):
        self.l = l
        self.msg_bit = msg_bit
        self.func_bit = func_bit
        self.k = k
        self.n = n
        self.m = m
        self.q = q
        self.U = U
        self.A = A
        self.alpha = alpha
        self.msk = Z

    def has_private_key(self) -> bool:
        return self.msk is not None

    def get_public_key(self):
        return _FeLWE_MK(self.l, self.msg_bit, self.func_bit, self.k, self.n, self.m, self.q, self.U, self.A, self.alpha)

    def export(self):
        pass


class _FeLWE_SK:
    def __init__(self, y: Matrix, Zy: Matrix):
        self.y = y
        self.Zy = Zy

    def export(self):
        pass


class _FeLWE_C:
    def __init__(self, c0: Matrix, c1: Matrix):
        self.c0 = c0
        self.c1 = c1

    def export(self):
        pass


class FeLWE:
    @staticmethod
    def sample(sigma1: float, sigma2: float, l: int, m: int):
        sys_random = random.SystemRandom()
        res = []
        half1 = m // 2
        half2 = m - half1
        for i in range(l):
            row1 = [round(sys_random.gauss(0, sigma1)) for _ in range(half1)]
            row2 = [round(sys_random.gauss(0, sigma2)) for _ in range(half2)]
            row2[i] += 1
            res.append(row1 + row2)
        return Matrix(res, dtype=object)

    @staticmethod
    def generate(l: int, msg_bit: int, func_bit: int, n: int = None) -> _FeLWE_MK:
        """
        Generate a FeLWE master key
        """
        k = l << (msg_bit + func_bit)

        if n is None:
            n = max(l, 64)

        q = getPrime(k.bit_length() * 2 + n.bit_length() * 15 + 10)
        alpha = 1 / (k * k * (n * q.bit_length()) ** 7)

        if q < math.sqrt(n) / alpha:
            raise Exception("q too small")

        m = n * q.bit_length()

        sigma1 = math.sqrt(n * m.bit_length()) * max(math.sqrt(m), k)
        sigma2 = math.sqrt((n ** 7) * m * (m.bit_length() ** 5)) * max(m, k * k)

        A = Matrix([[randbelow(q) for _ in range(n)] for _ in range(m)], dtype=object)
        Z = FeLWE.sample(sigma1, sigma2, l, m)

        U = (Z @ A) % q

        return _FeLWE_MK(l=l, msg_bit=msg_bit, func_bit=func_bit, k=k, n=n, m=m, q=q, U=U, A=A, alpha=alpha, Z=Z)

    @staticmethod
    def encrypt(x: List[int], pub: _FeLWE_MK) -> _FeLWE_C:
        if len(x) != pub.l:
            raise Exception("Encrypt vector must be of length l")

        sys_random = random.SystemRandom()

        s = Matrix([randbelow(pub.q) for _ in range(pub.n)], dtype=object)
        e0 = Matrix([round(sys_random.gauss(0, pub.alpha * pub.q)) for _ in range(pub.m)], dtype=object)
        e1 = Matrix([round(sys_random.gauss(0, pub.alpha * pub.q)) for _ in range(pub.l)], dtype=object)

        c0 = ((pub.A @ s) + e0) % pub.q
        c1 = ((pub.U @ s) + e1 + ((pub.q // pub.k) * Matrix(x, dtype=object))) % pub.q

        return _FeLWE_C(c0, c1)

    @staticmethod
    def decrypt(c: _FeLWE_C, pub: _FeLWE_MK, sk: _FeLWE_SK) -> int:
        u = ((sk.y @ c.c1) - (sk.Zy @ c.c0)) % pub.q
        factor = (pub.q // pub.k)
        minimum = factor

        answer = 0
        t1 = u // factor
        for i in range(t1 - 10, t1 + 10):
            u1 = i * factor - u
            if abs(u1) < minimum:
                minimum = abs(u1)
                answer = i

        if answer > pub.k//2:
            return answer - pub.k
        return answer

    @staticmethod
    def keygen(y: List[int], key: _FeLWE_MK) -> _FeLWE_SK:
        if len(y) != key.l:
            raise Exception(f"Function vector must be of length {key.l}")
        if not key.has_private_key():
            raise Exception("Private key not found in master key")
        y = Matrix(y, dtype=object)
        return _FeLWE_SK(y, y @ key.msk)
