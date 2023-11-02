import time
import logging
from tests.test_base import TestBase
from mife.multi.damgard import FeDamgardMulti
from mife.data.curve25519 import Curve25519
from mife.data.fastecdsa_wrapper import WrapCurve
from fastecdsa.curve import P192
import json


class TestFeDamgardMulti(TestBase):
    logging.getLogger().setLevel(logging.INFO)

    def test_export(self):
        n = 3
        m = 5
        x = [[i + j for j in range(m)] for i in range(n)]
        y = [[i - j + 10 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m)
        cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        json.dumps(key.export())
        [json.dumps(cs[i].export()) for i in range(n)]
        json.dumps(sk.export())
        json.dumps(key.get_public_key().export())


    def test_scheme_1(self):
        start = time.time()
        n = 3
        m = 5
        x = [[i + j for j in range(m)] for i in range(n)]
        y = [[i - j + 10 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m)
        cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        m = FeDamgardMulti.decrypt(cs, key.get_public_key(), sk, (0, 2000))
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
        res = FeDamgardMulti.decrypt(cs, key.get_public_key(), sk, (-10000000, 10000000))
        end = time.time()

        logging.info(f'FeDamgardMulti test scheme 2 performance with Prime Group (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)

    def test_scheme_3(self):
        start = time.time()
        n = 100
        m = 100
        x = [[1 for j in range(m)] for i in range(n)]
        y = [[1 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m)
        cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        res = FeDamgardMulti.decrypt(cs, key.get_public_key(), sk, (-100000, 100000))
        end = time.time()

        logging.info(f'FeDamgardMulti test scheme 3 performance with Prime Group(n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)

    def test_scheme_4(self):
        start = time.time()
        n = 50
        m = 50
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m, Curve25519)
        cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        res = FeDamgardMulti.decrypt(cs, key.get_public_key(), sk, (-10000000, 10000000))
        end = time.time()

        logging.info(f'FeDamgardMulti test scheme 4 performance with Curve25519 (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)

    def test_scheme_5(self):
        start = time.time()
        n = 50
        m = 50
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m, WrapCurve(P192))
        cs = [FeDamgardMulti.encrypt(x[i], key.get_enc_key(i)) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        res = FeDamgardMulti.decrypt(cs, key.get_public_key(), sk, (-10000000, 10000000))
        end = time.time()

        logging.info(f'FeDamgardMulti test scheme 5 performance with P192 (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)


