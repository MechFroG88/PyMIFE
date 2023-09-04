from __future__ import annotations

from typing import List, Self, Callable

class Matrix:
    @staticmethod
    def flatten(arr: List[List[int]]) -> List[int]:
        res = []
        for row in arr:
            res.extend(row)
        return res

    @staticmethod
    def unflatten(arr: List[int], n, m) -> List[List[int]]:
        res = []
        for i in range(n):
            res.append(arr[m * i: m * (i + 1)])
        return res

    def __init__(self, M: List[List[int] | int]):
        if len(M) == 0:
            raise Exception("Matrix can't be size 0x0")
        if isinstance(M[0], int):
            self._init_vector(M)
        else:
            self._init_matrix(M)

    def _init_vector(self, M: List[int]):
        self.isVector = True
        self.n = 1
        self.m = len(M)
        self.M = [[x for x in M]]

    def _init_matrix(self, M: List[List[int]]):
        self.isVector = False
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
            raise Exception(f"Matrix additional not supported for size {self.n} x {self.m} and {other.n} x {other.m}")

        return Matrix([[self.M[i][j] + other.M[i][j] for j in range(self.m)] for i in range(self.n)])

    def __rmul__(self, other: int):
        return Matrix([[other * self.M[i][j] for j in range(self.m)] for i in range(self.n)])

    def __mul__(self, other: Self) -> Self:
        if self.m != other.n:
            raise Exception(f"Matrix additional not supported for size {self.n} x {self.m} and {other.n} x {other.m}")
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
        if self.m != other.m:
            raise Exception(f"Dot product only application for vectors with same dimension")

        return sum([self.M[0][i] * other.M[0][i] for i in range(self.m)])
