from __future__ import annotations

import secrets

from mife.data.group import GroupBase, GroupElem
from typing import Self, TypedDict
from gmpy2 import powmod, gcd, invert, mpz
from Crypto.Util.number import isPrime


class Zmod(GroupBase):

    def __init__(self, modulus: int):
        if not isPrime(modulus):
            raise Exception("Modulus must be a prime number")
        self.modulus = modulus

    def __call__(self, elem: int) -> _ZmodElem:
        elem = elem % self.modulus
        return _ZmodElem(self, mpz(elem))

    def __eq__(self, other: Self) -> bool:
        return type(self) == type(other) and self.modulus == other.modulus

    def __str__(self) -> str:
        return f"Multiplicative Group of integer modulo {self.modulus}"

    def generator(self) -> _ZmodElem:
        while True:
            g = secrets.randbelow(self.modulus)
            g = (g ** 2) % self.modulus
            if gcd(g, self.modulus) != 1 or g == 1:
                continue
            if (self.modulus - 1) % g == 0:
                continue
            return _ZmodElem(self, mpz(g))

    def order(self) -> int:
        return self.modulus - 1

    def identity(self) -> _ZmodElem:
        return _ZmodElem(self, mpz(1))

    def export(self) -> dict:
        return {
            "type": "Zmod",
            "modulus": int(self.modulus)
        }


class _ZmodElem(GroupElem):

    def __init__(self, group: Zmod, val: mpz):
        self.group = group
        self.val = val

    def __add__(self, other: Self) -> Self:
        if self.group != other.group:
            return Exception(f"Addition not define for element of {self.group} and {other.group}")
        return _ZmodElem(self.group, (self.val * other.val) % self.group.modulus)

    def __neg__(self) -> Self:
        return _ZmodElem(self.group, invert(self.val, self.group.modulus))

    def __rmul__(self, other: int):
        return _ZmodElem(self.group, powmod(self.val, other, self.group.modulus))

    def __eq__(self, other):
        return type(self) == type(other) and self.group == other.group and self.val == other.val

    def __hash__(self):
        return hash(self.val)

    def __str__(self):
        return f"{self.val} in Multiplicative Group of integer modulo {self.group.modulus}"

    def export(self) -> dict:
        return {
            "val": int(self.val)
        }