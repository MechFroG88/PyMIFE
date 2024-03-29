import time
import logging
from tests.test_base import TestBase
from mife.single.quadratic.ddh import FeDDH

class TestFeDDH(TestBase):

    def test_scheme_1(self):
        start = time.time()
        n = 2
        x = [i + 2 for i in range(n)]
        y = [i + 3 for i in range(n)]
        f = [[i + j + 1 for j in range(n)] for i in range(n)]

        key = FeDDH.generate(n)
        c = FeDDH.encrypt(x, y, key)
        sk = FeDDH.keygen(f, key)
        m = FeDDH.decrypt(c, key.get_public_key(), sk, (0, 1000))
        end = time.time()

        logging.info(f'Quadratic FeDDH test scheme 1 performance (n={n}): {end - start}s')

        expected = 0
        for i in range(n):
            for j in range(n):
                expected += f[i][j] * x[i] * y[j]

        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 2
        x = [i - 2 for i in range(n)]
        y = [i + 3 for i in range(n)]
        f = [[i - j + 3 for j in range(n)] for i in range(n)]

        key = FeDDH.generate(n)
        c = FeDDH.encrypt(x, y, key)
        sk = FeDDH.keygen(f, key)
        m = FeDDH.decrypt(c, key.get_public_key(), sk, (-10000, 10000))
        end = time.time()

        logging.info(f'Quadratic FeDDH test scheme 2 performance (n={n}): {end - start}s')

        expected = 0
        for i in range(n):
            for j in range(n):
                expected += f[i][j] * x[i] * y[j]

        print(expected)

        self.assertEqual(expected, m)


