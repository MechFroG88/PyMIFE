from __future__ import annotations

from mife.data.group import GroupBase, GroupElem
from typing import Self, List
from gmpy2 import invert, mpz


class Curve25519(GroupBase):
    p = mpz(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed)
    a = mpz(0x76d06)
    b = mpz(0x01)
    g = (mpz(0x09), mpz(0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9))
    _order = mpz(0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed)

    def __call__(self, elem: List[int]) -> _Curve25519Elem:
        return _Curve25519Elem(self, *elem)

    def __eq__(self, other: Self) -> bool:
        return type(self) == type(other)

    def __str__(self) -> str:
        return f"Curve 25519"

    @staticmethod
    def order() -> int:
        return Curve25519._order

    @staticmethod
    def generator() -> _Curve25519Elem:
        return _Curve25519Elem(Curve25519.g[0], Curve25519.g[1])

    @staticmethod
    def identity() -> _Curve25519Elem:
        return _Curve25519Elem(0, 1, 0)

    def export(self) -> dict:
        return {
            "type": "Curve25519"
        }


class _Curve25519Elem(GroupElem):
    doubleConst = (Curve25519.a + 2) // 4

    def __init__(self, x, y, z=1):
        self.x = x
        self.y = y
        self.z = z

    def _double(self):
        l = (3 * self.x ** 2 + 2 * Curve25519.a * self.x + 1) * invert(2 * Curve25519.b * self.y, Curve25519.p)
        x = (Curve25519.b * l ** 2 - Curve25519.a - 2 * self.x) % Curve25519.p
        y = (l * (self.x - x) - self.y) % Curve25519.p
        return _Curve25519Elem(x, y)

    def _normalize(self):
        if self.z != 1 and self.z != 0:
            self.x = self.x * invert(self.z, Curve25519.p)
            self.z = 1
        self.x %= Curve25519.p
        self.y %= Curve25519.p

    def __add__(self, other: Self) -> Self:
        if self.z == 0:
            return other
        if other.z == 0:
            return self

        if self.x == other.x:
            if self.y == (-other.y) % Curve25519.p:
                return Curve25519.identity()
            return self._double()

        l = ((other.y - self.y) * invert(other.x - self.x, Curve25519.p)) % Curve25519.p
        x = (Curve25519.b * l ** 2 - Curve25519.a - self.x - other.x) % Curve25519.p
        y = (l * (self.x - x) - self.y) % Curve25519.p
        return _Curve25519Elem(x, y)

    def __neg__(self) -> Self:
        return _Curve25519Elem(self.x, -self.y, self.z)

    def _double_mont(self):
        a = ((self.x + self.z) ** 2) % Curve25519.p
        b = ((self.x - self.z) ** 2) % Curve25519.p
        c = (a - b) % Curve25519.p
        x = (a * b) % Curve25519.p
        z = (c * (b + self.doubleConst * c)) % Curve25519.p
        return _Curve25519Elem(x, 0, z)

    def _add_mont(self, other: Self, diff: Self):
        a = ((self.x - self.z) * (other.x + other.z)) % Curve25519.p
        b = ((self.x + self.z) * (other.x - other.z)) % Curve25519.p
        x = (diff.z * (a + b) ** 2) % Curve25519.p
        z = (diff.x * (a - b) ** 2) % Curve25519.p
        return _Curve25519Elem(x, 0, z)

    def __rmul__(self, val: int):
        val %= Curve25519.order()
        if val == 0:
            return Curve25519.identity()
        if val == Curve25519.order() - 1:
            return self.power(val)

        r0, r1 = (self, self._double_mont())
        diff = self

        bmask = 1 << 256
        while bmask > 0:
            if val & bmask:
                bmask >>= 1
                break
            bmask >>= 1

        while bmask > 0:
            if val & bmask:
                r0, r1 = (r0._add_mont(r1, diff), r1._double_mont())
            else:
                r0, r1 = r0._double_mont(), r0._add_mont(r1, diff)

            bmask >>= 1

        x = (r0.x * invert(r0.z, Curve25519.p)) % Curve25519.p
        x1 = (r1.x * invert(r1.z, Curve25519.p)) % Curve25519.p
        y = (diff.x * x + 1) * (diff.x + x + 2 * Curve25519.a)
        y = y - 2 * Curve25519.a - (diff.x - x) ** 2 * x1
        y = (y * invert(2 * Curve25519.b * diff.y, Curve25519.p)) % Curve25519.p

        return _Curve25519Elem(x, y)

    def power(self, x):
        x = x % Curve25519.order()
        res = Curve25519.identity()
        mul = self
        while x > 0:
            if x & 1:
                res = res + mul
            mul = mul + mul
            x >>= 1
        return res

    def __eq__(self, other):
        self._normalize()
        return self.x == other.x and self.y == other.y and self.z == other.z

    def __hash__(self):
        self._normalize()
        return hash(str(self.x) + str(self.y) + str(self.z))

    def __str__(self):
        self._normalize()
        return f'({self.x}:{self.y}:{self.z})'

    def export(self) -> dict:
        return {
            "x": self.x,
            "y": self.y,
            "z": self.z
        }

