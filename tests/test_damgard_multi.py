import time
import logging
from tests.test_base import TestBase
from src.mife.damgard_multi import FeDamgardMulti
import cProfile


class TestFeDamgardMulti(TestBase):
    logging.getLogger().setLevel(logging.INFO)

    def test_scheme_1(self):
        start = time.time()
        n = 3
        m = 5
        bits = 512
        x = [[i + j for j in range(m)] for i in range(n)]
        y = [[i - j + 10 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m, bits)
        cs = [FeDamgardMulti.encrypt(x[i], i, key) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        m = FeDamgardMulti.decrypt(cs, key, sk, (0, 2000))
        end = time.time()
        logging.info(f'FeDDHMulti test scheme 1 performance: {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 10
        m = 5
        bits = 512
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m, bits)
        cs = [FeDamgardMulti.encrypt(x[i], i, key) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        m = FeDamgardMulti.decrypt(cs, key, sk, (-100000, 100000))
        end = time.time()
        logging.info(f'FeDDHMulti test scheme 2 performance: {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, m)

