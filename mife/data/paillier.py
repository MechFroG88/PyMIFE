from __future__ import annotations
from Crypto.Util.number import inverse
from secrets import randbits
from mife.common import getStrongPrime
from math import gcd
from gmpy2 import mpz


class PaillierKey:
    def __init__(self, n, g, lcm=None):
        self.n = n
        self.g = g
        self.lcm = lcm
        self.n2 = self.n ** 2
        if lcm is not None:
            self.u = inverse(lcm, n)

    def getPublicKey(self):
        return PaillierKey(self.n, self.g)

    def hasPrivateKey(self):
        return self.u is not None

    def encrypt(self, m: int):
        while True:
            r = randbits(self.n.bit_length())
            if r < self.n and gcd(r, self.n) == 1:
                break
        return PaillierElem(self.getPublicKey(), (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2)

    def decrypt(self, c: PaillierElem) -> int:
        if not self.hasPrivateKey():
            raise ValueError("No private key")
        return (((pow(c.c, self.lcm, self.n2) - 1) // self.n) * self.u) % self.n


class PaillierElem:
    def __init__(self, pk: PaillierKey, c: int):
        self.pk = pk
        self.c = c

    def __add__(self, other):
        if self.pk.n != other.pk.n:
            raise ValueError("Different public keys")
        return PaillierElem(self.pk, (self.c * other.c) % self.pk.n2)

    def __radd__(self, other):
        if other == 0:
            return self
        raise ValueError("Invalid operation")

    def __rmul__(self, other: int):
        return PaillierElem(self.pk, pow(self.c, other, self.pk.n2))


class Paillier:
    @staticmethod
    def generate(bits=1024, p=None, q=None):
        if p is None:
            p = getStrongPrime(bits)
        if q is None:
            q = getStrongPrime(bits)
        n = p * q
        g = n + 1
        lcm = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
        return PaillierKey(mpz(n), mpz(g), mpz(lcm))





