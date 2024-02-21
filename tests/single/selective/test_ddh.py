import time
import logging
import json

from tests.test_base import TestBase
from mife.single.selective.ddh import FeDDH


class TestFeDDH(TestBase):

    def test_export(self):
        n = 10
        x = [i for i in range(n)]
        key = FeDDH.generate(n)
        c = FeDDH.encrypt(x, key)
        sk = FeDDH.keygen(x, key)
        json.dumps(key.export())
        json.dumps(c.export())
        json.dumps(sk.export())
        json.dumps(key.get_public_key().export())

    def test_scheme_1(self):
        start = time.time()
        n = 10
        x = [i for i in range(n)]
        y = [i + 10 for i in range(n)]
        key = FeDDH.generate(n)
        c = FeDDH.encrypt(x, key)
        sk = FeDDH.keygen(y, key)
        m = FeDDH.decrypt(c, key.get_public_key(), sk, (0, 1000))
        end = time.time()

        logging.info(f'FeDDH test scheme 1 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 20
        x = [i for i in range(n)]
        y = [-(i * 10 + 2) for i in range(n)]
        key = FeDDH.generate(n)
        c = FeDDH.encrypt(x, key)
        sk = FeDDH.keygen(y, key)
        m = FeDDH.decrypt(c, key.get_public_key(), sk, (-100000, 100000))
        end = time.time()

        logging.info(f'FeDDH test scheme 2 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

    def test_scheme_3(self):
        start = time.time()
        n = 10000
        x = [1 for i in range(n)]
        y = [1 for i in range(n)]
        key = FeDDH.generate(n)
        c = FeDDH.encrypt(x, key)
        sk = FeDDH.keygen(y, key)
        m = FeDDH.decrypt(c, key.get_public_key(), sk, (0, 200000))
        end = time.time()

        logging.info(f'FeDDH test scheme 3 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

