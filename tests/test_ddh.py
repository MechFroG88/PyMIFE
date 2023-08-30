import time
import logging

from tests.test_base import TestBase
from src.mife.ddh import FeDDH


class TestFeDDH(TestBase):
    def test_generate(self):
        n = 10
        bits = 1024
        key = FeDDH.generate(n, bits)
        self.assertEqual(len(key.msk), n)
        self.assertEqual(len(key.mpk), n)
        self.assertEqual(key.p.bit_length(), bits)

        for i in range(n):
            self.assertEqual(key.mpk[i], pow(key.g, key.msk[i], key.p))

    def test_keygen(self):
        n = 10
        bits = 1024
        key = FeDDH.generate(n, bits)
        y = [i for i in range(n)]
        sk = FeDDH.keygen(y, key)
        self.assertEqual(sk.y, y)
        self.assertEqual(sk.sk, sum([a * b for a, b in zip(y, key.msk)]))

    def test_scheme_1(self):
        start = time.time()
        n = 10
        bits = 512
        x = [i for i in range(n)]
        y = [i + 10 for i in range(n)]
        key = FeDDH.generate(n, bits)
        c = FeDDH.encrypt(x, key)
        sk = FeDDH.keygen(y, key)
        m = FeDDH.decrypt(c, key, sk, (0, 1000))
        end = time.time()

        logging.info(f'FeDDH test scheme 1 performance: {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 20
        bits = 512
        x = [i for i in range(n)]
        y = [-(i * 10 + 2) for i in range(n)]
        key = FeDDH.generate(n, bits)
        c = FeDDH.encrypt(x, key)
        sk = FeDDH.keygen(y, key)
        m = FeDDH.decrypt(c, key, sk, (-100000, 100000))
        end = time.time()

        logging.info(f'FeDDH test scheme 2 performance: {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

