from __future__ import annotations

from mife.data.pairing import PairingBase, GroupElem
from py_ecc.bn128.bn128_pairing import pairing, curve_order
from py_ecc.bn128.bn128_curve import (G1, G2, FQ, FQ2, FQ12, add, neg, eq, multiply)
from py_ecc.typing import Point2D


class Bn128Pairing(PairingBase):

    def __init__(self):
        self.identity_t = None

    def order(self) -> int:
        return curve_order

    def generator1(self) -> Bn128PairingPoint1:
        return Bn128PairingPoint1(G1)

    def generator2(self) -> Bn128PairingPoint2:
        return Bn128PairingPoint2(G2)

    def generatorT(self) -> Bn128PairingPointT:
        if self.identity_t is None:
            self.identity_t = Bn128PairingPointT(pairing(G2, G1))
        return self.identity_t

    def identity1(self) -> GroupElem:
        return Bn128PairingPoint1(None)

    def identity2(self) -> GroupElem:
        return Bn128PairingPoint2(None)

    def identityT(self) -> GroupElem:
        return Bn128PairingPointT(None)

    def pairing(self, g1: Bn128PairingPoint1, g2: Bn128PairingPoint2) -> GroupElem:
        return Bn128PairingPointT(pairing(g2.point, g1.point))


class Bn128PairingPoint1(GroupElem):

    def __init__(self, point: Point2D[FQ]):
        self.point = point

    def __add__(self, other):
        return Bn128PairingPoint1(add(self.point, other.point))

    def __neg__(self):
        return Bn128PairingPoint1(neg(self.point))

    def __rmul__(self, other):
        return Bn128PairingPoint1(multiply(self.point, other))

    def __eq__(self, other):
        return eq(self.point, other.point)

    def __hash__(self):
        pass

    def export(self) -> dict:
        pass


class Bn128PairingPoint2(GroupElem):

    def __init__(self, point: Point2D[FQ2]):
        self.point = point

    def __add__(self, other):
        return Bn128PairingPoint2(add(self.point, other.point))

    def __neg__(self):
        return Bn128PairingPoint2(neg(self.point))

    def __rmul__(self, other):
        return Bn128PairingPoint2(multiply(self.point, other))

    def __eq__(self, other):
        return eq(self.point, other.point)

    def __hash__(self):
        pass

    def export(self) -> dict:
        pass


class Bn128PairingPointT(GroupElem):

    def __init__(self, val: FQ12):
        self.val = val

    def __add__(self, other):
        return Bn128PairingPointT(self.val * other.val)

    def __neg__(self):
        return Bn128PairingPointT(FQ12.one() / self.val)

    def __rmul__(self, other):
        return Bn128PairingPointT(self.val ** other)

    def __eq__(self, other):
        return self.val == other.val

    def __hash__(self):
        return hash(str(self.val))

    def export(self) -> dict:
        pass
