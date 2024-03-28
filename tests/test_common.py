import time
import logging

from mife.data.zmod_r import ZmodR
from tests.test_base import TestBase
from Crypto.Util.number import getStrongPrime
from mife.data.matrix import Matrix
from mife.common import invertible_matrix
from secrets import randbelow
from gmpy2 import powmod

class TestCommon(TestBase):

    def test_pow(self):
        p = getStrongPrime(512)
        g = 2
        exp = [randbelow(p) for _ in range(10)]
        start1 = time.time()
        [powmod(g, e, p) for e in exp]
        end1 = time.time()
        start2 = time.time()
        [pow(g, e, p) for e in exp]
        end2 = time.time()

        logging.info(f'gmpy2 : {end1 - start1}s')
        logging.info(f'python pow : {end2 - start2}s')

    def test_invertible_matrix(self):
        G = ZmodR(101)
        n = 10
        start1 = time.time()
        A = invertible_matrix(G, n)
        Ai = A.inverse()
        self.assertEqual(A * Ai, Matrix([[G(int(i == j)) for j in range(n)] for i in range(n)]))
        self.assertEqual(A.determinant() * Ai.determinant(), 1)
        end1 = time.time()
        logging.info(f'invertible_matrix : {end1 - start1}s')
