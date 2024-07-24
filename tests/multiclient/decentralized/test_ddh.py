import time
import logging

from mife.data.curve25519 import Curve25519
from tests.test_base import TestBase
from mife.multiclient.decentralized.ddh import FeDDHMultiClientDec

class TestFeDDHMultiClient(TestBase):
    logging.getLogger().setLevel(logging.INFO)

    def test_scheme_1(self):
        start = time.time()
        n = 3
        m = 5
        x = [[i + j for j in range(m)] for i in range(n)]
        y = [[i - j + 10 for j in range(m)] for i in range(n)]
        tag = b"testingtag123"
        pub = FeDDHMultiClientDec.generate(n, m)
        keys = [pub.generate_party(i) for i in range(n)]

        for i in range(n):
            for j in range(n):
                if i == j: continue
                keys[i].exchange(j, keys[j].get_exc_public_key())

        for i in range(n):
            keys[i].generate_share()

        cs = [FeDDHMultiClientDec.encrypt(x[i], tag, keys[i]) for i in range(n)]
        sk = [FeDDHMultiClientDec.keygen(y, keys[i]) for i in range(n)]
        m = FeDDHMultiClientDec.decrypt(cs, tag, pub, sk, (0, 2000))
        end = time.time()
        logging.info(f'FeDDHMultiClient test scheme 1 performance with Prime Group (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 25
        m = 25
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        tag = str(start).encode()
        pub = FeDDHMultiClientDec.generate(n, m)
        keys = [pub.generate_party(i) for i in range(n)]
        for i in range(n):
            for j in range(n):
                if i == j: continue
                keys[i].exchange(j, keys[j].get_exc_public_key())

        for i in range(n):
            keys[i].generate_share()

        cs = [FeDDHMultiClientDec.encrypt(x[i], tag, keys[i]) for i in range(n)]
        sk = [FeDDHMultiClientDec.keygen(y, keys[i]) for i in range(n)]
        res = FeDDHMultiClientDec.decrypt(cs, tag, pub, sk, (-10000000, 10000000))
        end = time.time()
        logging.info(f'FeDDHMultiClient test scheme 2 performance with Prime Group (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)

    def test_scheme_3(self):
        start = time.time()
        n = 10
        m = 100
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        tag = str(start).encode()
        pub = FeDDHMultiClientDec.generate(n, m, Curve25519)
        keys = [pub.generate_party(i) for i in range(n)]
        for i in range(n):
            for j in range(n):
                if i == j: continue
                keys[i].exchange(j, keys[j].get_exc_public_key())

        for i in range(n):
            keys[i].generate_share()

        cs = [FeDDHMultiClientDec.encrypt(x[i], tag, keys[i]) for i in range(n)]
        sk = [FeDDHMultiClientDec.keygen(y, keys[i]) for i in range(n)]
        res = FeDDHMultiClientDec.decrypt(cs, tag, pub, sk, (-10000000, 10000000))
        end = time.time()

        logging.info(f'FeDDHMultiClient test scheme 3 performance with Curve25519 (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)