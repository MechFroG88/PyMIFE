from __future__ import annotations

from multiprocessing import Pool
from typing import List, Optional, Self, Callable
from gmpy2 import powmod


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

    def __init__(self, M: List[List[int] | int], p: Optional[int] = None):
        self.p = p
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
        self.M = [[self._mod(x) for x in M]]

    def _init_matrix(self, M: List[List[int]]):
        self.isVector = False
        self.n = len(M)
        self.m = len(M[0])
        self.M = []
        for i in range(self.n):
            if len(M[i]) != self.m:
                raise Exception("Matrix size not consistent")
            self.M.append([self._mod(x) for x in M[i]])

    def _mod(self, v):
        if self.p is None:
            return v
        return v % self.p

    @property
    def T(self) -> Self:
        m = [[self.M[j][i] for j in range(self.n)] for i in range(self.m)]
        return Matrix(m, self.p)

    def __add__(self, other: Self) -> Self:
        if self.n != other.n or self.m != other.m:
            raise Exception(f"Matrix additional not supported for size {self.n} x {self.m} and {other.n} x {other.m}")
        if self.p != other.p:
            raise Exception(f"Matrix must be in the same field")

        return Matrix([[self._mod(self.M[i][j] + other.M[i][j]) for j in range(self.m)] for i in range(self.n)], self.p)

    # @staticmethod
    # def _pow_lambda(g, a, p):
    #     return powmod(g, a, p)
    #
    # def __pow__(self, a: int) -> Self:
    #     if self.p is None:
    #         raise Exception(f"Matrix pow only supported when the field is finite")
    #     with Pool() as p:
    #         new_flat_m = p.starmap(
    #             Matrix._pow_lambda,
    #             [(self.M[i][j], a, self.p) for i in range(self.n) for j in range(self.m)]
    #         )
    #
    #     return Matrix(self.unflatten(new_flat_m, self.n, self.m), self.p)

    def __pow__(self, a: int) -> Self:
        if self.p is None:
            raise Exception(f"Matrix pow only supported when the field is finite")

        return Matrix([[powmod(self.M[i][j], a, self.p) for j in range(self.m)] for i in range(self.n)], self.p)

    # @staticmethod
    # def _mul_lambda(i, j, self: Matrix, other: Matrix):
    #     return self._mod(sum([self.M[i][k] * other.M[k][j] for k in range(self.m)]))
    #
    # def __mul__(self, other: Self) -> Self:
    #     if self.m != other.n:
    #         raise Exception(f"Matrix additional not supported for size {self.n} x {self.m} and {other.n} x {other.m}")
    #     with Pool() as p:
    #         new_flat_m = p.starmap(
    #             Matrix._mul_lambda,
    #             [(i, j, self, other) for i in range(self.n) for j in range(other.m)]
    #         )
    #
    #     return Matrix(self.unflatten(new_flat_m, self.n, other.m), self.p)

    def __mul__(self, other: Self) -> Self:
        if self.m != other.n:
            raise Exception(f"Matrix additional not supported for size {self.n} x {self.m} and {other.n} x {other.m}")
        new_flat_m = [self._mod(sum([self.M[i][k] * other.M[k][j] for k in range(self.m)])) for i in range(self.n) for j
                      in range(other.m)]
        return Matrix(self.unflatten(new_flat_m, self.n, other.m), self.p)

    def __getitem__(self, index) -> List[int]:
        return self.M[index]

    def point_mul(self, other: Self) -> Self:
        if self.n != other.n or self.m != other.m:
            raise Exception(
                f"Matrix point multiplication not supported for size {self.n} x {self.m} and {other.n} x {other.m}")
        if self.p != other.p:
            raise Exception(f"Matrix must be in the same field")

        return Matrix([[self._mod(self.M[i][j] * other.M[i][j]) for j in range(self.m)] for i in range(self.n)], self.p)

    # @staticmethod
    # def _apply_func_lambda(x, func):
    #     return func(x)
    #
    # def apply_func(self, func: Callable, prime=None) -> Self:
    #     with Pool() as p:
    #         new_flat_m = p.starmap(
    #             Matrix._apply_func_lambda,
    #             [(self.M[i][j], func) for i in range(self.n) for j in range(self.m)]
    #         )
    #
    #     return Matrix(
    #         self.unflatten(new_flat_m, self.n, self.m),
    #         self.p if prime is None else prime
    #     )

    def apply_func(self, func: Callable, prime=None) -> Self:
        return Matrix(
            [[func(self.M[i][j]) for j in range(self.m)] for i in range(self.n)],
            self.p if prime is None else prime
        )

    def change_field(self, p: int) -> Self:
        if self.p != None:
            raise Exception(f"Matrix change field only supported in Matrix over infinite field")

        return Matrix(self.M, p)

    def row(self, i) -> Self:
        return Matrix(self.M[i], self.p)

    def dot(self, other: Self) -> int:
        if not (self.isVector and other.isVector):
            raise Exception(f"Dot product only applicable for vector")
        if self.m != other.m:
            raise Exception(f"Dot product only application for vectors with same dimension")

        return self._mod(sum([self.M[0][i] * other.M[0][i] for i in range(self.m)]))
