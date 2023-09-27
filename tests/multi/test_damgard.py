import time
import logging
from tests.test_base import TestBase
from mife.multi.damgard import FeDamgardMulti
from mife.data.curve25519 import Curve25519


class TestFeDamgardMulti(TestBase):
    logging.getLogger().setLevel(logging.INFO)

    def test_scheme_1(self):
        start = time.time()
        n = 3
        m = 5
        x = [[i + j for j in range(m)] for i in range(n)]
        y = [[i - j + 10 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m)
        cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        m = FeDamgardMulti.decrypt(cs, key, sk, (0, 2000))
        end = time.time()
        logging.info(f'FeDamgardMulti test scheme 1 performance with Prime Group (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 50
        m = 50
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m)
        cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        res = FeDamgardMulti.decrypt(cs, key, sk, (-10000000, 10000000))
        end = time.time()

        logging.info(f'FeDamgardMulti test scheme 2 performance with Prime Group (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)

    def test_scheme_3(self):
        start = time.time()
        n = 50
        m = 50
        x = [[1 for j in range(m)] for i in range(n)]
        y = [[1 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m)
        cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        res = FeDamgardMulti.decrypt(cs, key, sk, (-100000, 100000))
        end = time.time()

        logging.info(f'FeDamgardMulti test scheme 3 performance with Prime Group(n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)

    def test_scheme_4(self):
        start = time.time()
        n = 25
        m = 25
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m, Curve25519)
        cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        res = FeDamgardMulti.decrypt(cs, key, sk, (-10000000, 10000000))
        end = time.time()

        logging.info(f'FeDamgardMulti test scheme 4 performance with Curve25519 (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)

