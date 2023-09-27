from __future__ import annotations

from typing import List, Self, Callable, Any

class Matrix:
    @staticmethod
    def flatten(arr: List[List[Any]]) -> List[Any]:
        res = []
        for row in arr:
            res.extend(row)
        return res

    @staticmethod
    def unflatten(arr: List[Any], n, m) -> List[List[Any]]:
        res = []
        for i in range(n):
            res.append(arr[m * i: m * (i + 1)])
        return res

    @property
    def isVector(self):
        return self.n == 1 or self.m == 1

    def __init__(self, M: List[List[Any] | Any]):
        if len(M) == 0:
            raise Exception("Matrix can't be size 0x0")
        if isinstance(M[0], list):
            self._init_matrix(M)
        else:
            self._init_vector(M)

    def _init_vector(self, M: List[Any]):
        self.n = 1
        self.m = len(M)
        self.M = [[x for x in M]]

    def _init_matrix(self, M: List[List[Any]]):
        self.n = len(M)
        self.m = len(M[0])
        self.M = []
        for i in range(self.n):
            if len(M[i]) != self.m:
                raise Exception("Matrix size not consistent")
            self.M.append([x for x in M[i]])

    @property
    def T(self) -> Self:
        m = [[self.M[j][i] for j in range(self.n)] for i in range(self.m)]
        return Matrix(m)

    def __add__(self, other: Self) -> Self:
        if self.n != other.n or self.m != other.m:
            raise Exception(f"Matrix addition not supported for size {self.n} x {self.m} and {other.n} x {other.m}")

        return Matrix([[self.M[i][j] + other.M[i][j] for j in range(self.m)] for i in range(self.n)])

    def __rmul__(self, other: int):
        return Matrix([[other * self.M[i][j] for j in range(self.m)] for i in range(self.n)])

    def __mul__(self, other: Self) -> Self:
        if isinstance(other, int):
            return self.__rmul__(other)
        if self.m != other.n:
            raise Exception(f"Matrix multiplication not supported for size {self.n} x {self.m} and {other.n} x {other.m}")
        new_flat_m = [sum([self.M[i][k] * other.M[k][j] for k in range(self.m)])
                      for i in range(self.n) for j in range(other.m)]
        return Matrix(self.unflatten(new_flat_m, self.n, other.m))

    def __getitem__(self, index) -> List[int]:
        return self.M[index]

    def apply_func(self, func: Callable) -> Self:
        return Matrix([[func(self.M[i][j]) for j in range(self.m)] for i in range(self.n)])

    def row(self, i) -> Self:
        return Matrix(self.M[i])

    def dot(self, other: Self) -> int:
        if not (self.isVector and other.isVector):
            raise Exception(f"Dot product only applicable for vector")

        arr1 = self.flatten(self.M)
        arr2 = self.flatten(other.M)

        if len(arr1) != len(arr2):
            raise Exception("Dimension different for dot product")

        cul = arr1[0] * arr2[0]
        for i in range(1, len(arr1)):
            cul += arr1[i] * arr2[i]
        return cul


    def __str__(self):
        s = "[\n"
        for i in self.M:
            s += "\t[ "
            for j in i:
                s += str(j)
                s += " "
            s += "]\n"
        s += "]"
        return s