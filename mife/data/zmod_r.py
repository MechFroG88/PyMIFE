from __future__ import annotations

from typing import Self
from gmpy2 import mpz
from Crypto.Util.number import inverse


class ZmodR():

    def __init__(self, modulus: int):
        self.modulus = modulus

    def __call__(self, elem: int) -> _ZmodRElem:
        elem = elem % self.modulus
        return _ZmodRElem(self, mpz(elem))

    def __eq__(self, other: Self) -> bool:
        return type(self) == type(other) and self.modulus == other.modulus

    def __str__(self) -> str:
        return f"Multiplicative Group of integer modulo {self.modulus}"

    def order(self) -> int:
        return self.modulus

    def export(self) -> dict:
        return {
            "type": "Zmod",
            "modulus": self.modulus
        }

    def identity(self) -> _ZmodRElem:
        return _ZmodRElem(self, mpz(0))


class _ZmodRElem():

    def __init__(self, group: ZmodR, val: mpz):
        self.group = group
        self._val = val

    @property
    def val(self):
        self._val = self._val % self.group.modulus
        return self._val

    def __radd__(self, other):
        return self.__add__(other)

    def __add__(self, other: Self) -> Self:
        if isinstance(other, int) or isinstance(other, mpz):
            return _ZmodRElem(self.group, (self._val + other) % self.group.modulus)
        if self.group != other.group:
            return Exception(f"Addition not define for element of {self.group} and {other.group}")
        return _ZmodRElem(self.group, (self._val + other._val) % self.group.modulus)

    def __rsub__(self, other):
        return _ZmodRElem(self.group, (other - self._val) % self.group.modulus)

    def __neg__(self) -> Self:
        return _ZmodRElem(self.group, -self._val)

    def __sub__(self, other):
        return self.__add__(-other)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __mul__(self, other: _ZmodRElem):
        if isinstance(other, int) or isinstance(other, mpz):
            return _ZmodRElem(self.group, (self._val * other) % self.group.modulus)
        return _ZmodRElem(self.group, (self._val * other._val) % self.group.modulus)

    def __truediv__(self, other):
        if isinstance(other, int):
            return self.__mul__(_ZmodRElem(self.group, mpz(inverse(other, self.group.modulus))))
        return self.__mul__(_ZmodRElem(self.group, mpz(inverse(other._val, self.group.modulus))))

    def __rtruediv__(self, other):
        return _ZmodRElem(self.group, other * mpz(inverse(self._val, self.group.modulus)))

    def __eq__(self, other):
        if (isinstance(other, int) or isinstance(other, mpz)):
            return self.val == _ZmodRElem(self.group, other).val
        return type(self) == type(other) and self.group == other.group and self.val == other.val

    def __int__(self):
        return int(self.val)

    def __hash__(self):
        return hash(self.val)

    def __str__(self):
        return str(self.val)