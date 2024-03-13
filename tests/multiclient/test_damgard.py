import time
import logging
from tests.test_base import TestBase
from mife.multiclient.damgard import FeDamgardMultiClient
import json


class TestFeDamgardMultiClient(TestBase):
    logging.getLogger().setLevel(logging.INFO)

    def test_scheme_1(self):
        start = time.time()
        n = 3
        m = 5
        x = [[i + j for j in range(m)] for i in range(n)]
        y = [[i - j + 10 for j in range(m)] for i in range(n)]
        tag = b"testingtag123"
        key = FeDamgardMultiClient.generate(n, m)
        cs = [FeDamgardMultiClient.encrypt(x[i], tag, key.get_enc_key(i), key.get_public_key()) for i in range(n)]
        sk = FeDamgardMultiClient.keygen(y, key)
        m = FeDamgardMultiClient.decrypt(cs, key.get_public_key(), sk, (0, 2000))
        end = time.time()
        logging.info(f'FeDamgardMultiClient test scheme 1 performance with Prime Group (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 10
        m = 10
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        tag = str(start).encode()
        key = FeDamgardMultiClient.generate(n, m)
        cs = [FeDamgardMultiClient.encrypt(x[i], tag, key.get_enc_key(i), key.get_public_key()) for i in range(n)]
        sk = FeDamgardMultiClient.keygen(y, key)
        res = FeDamgardMultiClient.decrypt(cs, key.get_public_key(), sk, (-10000000, 10000000))
        end = time.time()

        logging.info(f'FeDamgardMultiClient test scheme 2 performance with Prime Group (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)

    def test_scheme_3(self):
        start = time.time()
        n = 25
        m = 25
        x = [[1 for j in range(m)] for i in range(n)]
        y = [[1 for j in range(m)] for i in range(n)]
        tag = str(start).encode()
        key = FeDamgardMultiClient.generate(n, m)
        cs = [FeDamgardMultiClient.encrypt(x[i], tag, key.get_enc_key(i), key.get_public_key()) for i in range(n)]
        sk = FeDamgardMultiClient.keygen(y, key)
        res = FeDamgardMultiClient.decrypt(cs, key.get_public_key(), sk, (-100000, 100000))
        end = time.time()

        logging.info(f'FeDamgardMultiClient test scheme 3 performance with Prime Group (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)

    def test_scheme_safe_1(self):
        start = time.time()
        n = 10
        m = 10
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        tag = str(start).encode()
        key = FeDamgardMultiClient.generate(n, m)
        cs = [FeDamgardMultiClient.encrypt(x[i], tag, key.get_enc_key(i), key.get_public_key()) for i in range(n)]
        sk = FeDamgardMultiClient.keygen_safe(y, key, cs)
        res = FeDamgardMultiClient.decrypt_safe(cs, key.get_public_key(), sk, (-10000000, 10000000))
        end = time.time()

        logging.info(f'FeDamgardMultiClient test scheme 2 performance with Prime Group (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)
