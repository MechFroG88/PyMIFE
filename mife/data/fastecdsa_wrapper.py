from mife.data.group import GroupBase, GroupElem
from fastecdsa.curve import Curve
from fastecdsa.point import Point

class WrapCurve(GroupBase):

    def __init__(self, curve: Curve):
        self.curve = curve

    def order(self) -> int:
        return self.curve.q

    def identity(self) -> GroupElem:
        return WrapPoint(Point(0, 0, curve=None))

    def generator(self) -> GroupElem:
        return WrapPoint(self.curve.G)

class WrapPoint(GroupElem):

    def __init__(self, point: Point):
        self.point = point

    def __add__(self, other):
        return WrapPoint(self.point + other.point)

    def __neg__(self):
        return WrapPoint(-self.point)

    def __rmul__(self, other):
        return WrapPoint(self.point * other)

    def __eq__(self, other):
        return self.point == other.point

    def __hash__(self):
        return hash(str(self.point.x) + "," + str(self.point.y))