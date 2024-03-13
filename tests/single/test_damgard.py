import time
import logging
from tests.test_base import TestBase
from mife.single.damgard import FeDamgard
import json


class TestFeDamgard(TestBase):

    def test_export(self):
        n = 10
        x = [i for i in range(n)]
        key = FeDamgard.generate(n)
        c = FeDamgard.encrypt(x, key)
        sk = FeDamgard.keygen(x, key)
        json.dumps(key.export())
        json.dumps(c.export())
        json.dumps(sk.export())
        json.dumps(key.get_public_key().export())

    def test_scheme_1(self):
        start = time.time()
        n = 10
        x = [i for i in range(n)]
        y = [i + 10 for i in range(n)]
        key = FeDamgard.generate(n)
        c = FeDamgard.encrypt(x, key)
        sk = FeDamgard.keygen(y, key)
        m = FeDamgard.decrypt(c, key.get_public_key(), sk, (0, 1000))
        end = time.time()

        logging.info(f'FeDamgard test scheme 1 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 20
        x = [i for i in range(n)]
        y = [-(i * 10 + 2) for i in range(n)]
        key = FeDamgard.generate(n)
        c = FeDamgard.encrypt(x, key)
        sk = FeDamgard.keygen(y, key)
        m = FeDamgard.decrypt(c, key.get_public_key(), sk, (-100000, 100000))
        end = time.time()

        logging.info(f'FeDamgard test scheme 2 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

    def test_scheme_3(self):
        start = time.time()
        n = 1000
        x = [1 for i in range(n)]
        y = [1 for i in range(n)]
        key = FeDamgard.generate(n)
        c = FeDamgard.encrypt(x, key)
        sk = FeDamgard.keygen(y, key)
        m = FeDamgard.decrypt(c, key.get_public_key(), sk, (0, 1000000))
        end = time.time()

        logging.info(f'FeDamgard test scheme 3 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

    def test_scheme_safe_1(self):
        start = time.time()
        n = 20
        x = [i for i in range(n)]
        y = [-(i * 10 + 2) for i in range(n)]
        key = FeDamgard.generate(n)
        c = FeDamgard.encrypt(x, key)
        sk = FeDamgard.keygen_safe(y, key, c)
        m = FeDamgard.decrypt_safe(c, key.get_public_key(), sk, (-100000, 100000))
        end = time.time()

        logging.info(f'FeDamgard test scheme 2 performance (n={n}): {end - start}s')

        expected = sum([a * b for a, b in zip(x, y)])
        self.assertEqual(expected, m)

