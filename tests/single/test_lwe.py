import time
import logging

from tests.test_base import TestBase
from mife.single.lwe import FeLWE


class TestFeLWE(TestBase):

    def test_scheme_1(self):
        start = time.time()
        n = 10
        x = [i - 10 for i in range(n)]
        y = [i for i in range(n)]
        key = FeLWE.generate(n, 4, 4)
        c = FeLWE.encrypt(x, key)
        sk = FeLWE.keygen(y, key)
        m = FeLWE.decrypt(c, key, sk)
        end = time.time()

        logging.info(f'FeLWE test scheme 1 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 20
        x = [(i * 10 + 2) for i in range(n)]
        y = [31 for i in range(n)]
        key = FeLWE.generate(n, 5, 5)
        c = FeLWE.encrypt(x, key)
        sk = FeLWE.keygen(y, key)
        m = FeLWE.decrypt(c, key, sk)
        end = time.time()

        logging.info(f'FeDDH test scheme 2 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected % key.p, m)

    def test_scheme_3(self):
        start = time.time()
        n = 100
        x = [i for i in range(n)]
        y = [i for i in range(n)]
        key = FeLWE.generate(n, 7, 7)
        c = FeLWE.encrypt(x, key)
        sk = FeLWE.keygen(y, key)
        m = FeLWE.decrypt(c, key, sk)
        end = time.time()

        logging.info(f'FeDamgard test scheme 3 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

    def test_scheme_4(self):
        start = time.time()
        n = 10
        x = [(i + 10) for i in range(n)]
        y = [2 for i in range(n)]
        key = FeLWE.generate(n, 5, 2)
        c = FeLWE.encrypt(x, key)
        sk = FeLWE.keygen(y, key)
        m = FeLWE.decrypt(c, key, sk)
        end = time.time()

        logging.info(f'FeDamgard test scheme 3 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

