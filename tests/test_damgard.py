import time
import logging
from tests.test_base import TestBase
from src.mife.damgard import FeDamgard


class TestFeDamgard(TestBase):
    def test_generate(self):
        n = 10
        bits = 1024
        key = FeDamgard.generate(n, bits)
        self.assertEqual(len(key.msk), n)
        self.assertEqual(len(key.mpk), n)
        self.assertEqual(key.p.bit_length(), bits)

        for i in range(n):
            expected = (pow(key.g, key.msk[i][0], key.p) * pow(key.h, key.msk[i][1], key.p)) % key.p
            self.assertEqual(key.mpk[i], expected)

    def test_keygen(self):
        n = 10
        bits = 1024
        key = FeDamgard.generate(n, bits)
        y = [i for i in range(n)]
        sk = FeDamgard.keygen(y, key)
        self.assertEqual(sk.y, y)
        self.assertEqual(sk.sx, sum([key.msk[i][0] * y[i] for i in range(n)]))
        self.assertEqual(sk.tx, sum([key.msk[i][1] * y[i] for i in range(n)]))

    def test_scheme_1(self):
        start = time.time()
        n = 10
        bits = 512
        x = [i for i in range(n)]
        y = [i + 10 for i in range(n)]
        key = FeDamgard.generate(n, bits)
        c = FeDamgard.encrypt(x, key)
        sk = FeDamgard.keygen(y, key)
        m = FeDamgard.decrypt(c, key, sk, (0, 1000))
        end = time.time()

        logging.info(f'FeDamgard test scheme 1 performance: {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 20
        bits = 512
        x = [i for i in range(n)]
        y = [-(i * 10 + 2) for i in range(n)]
        key = FeDamgard.generate(n, bits)
        c = FeDamgard.encrypt(x, key)
        sk = FeDamgard.keygen(y, key)
        m = FeDamgard.decrypt(c, key, sk, (-100000, 100000))
        end = time.time()

        logging.info(f'FeDamgard test scheme 2 performance: {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

