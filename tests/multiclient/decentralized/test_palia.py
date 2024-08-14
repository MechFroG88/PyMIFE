import time
import logging

from mife.data.curve25519 import Curve25519
from tests.test_base import TestBase
from mife.multiclient.decentralized.palia import Palia

class TestPalia(TestBase):
    logging.getLogger().setLevel(logging.INFO)

    def test_scheme_1(self):
        start = time.time()
        n = 3
        m = 5
        x = [[i + j for j in range(m)] for i in range(n)]
        y = [[i - j + 10 for j in range(m)] for i in range(n)]
        tag = b"testingtag123"
        pub = Palia.generate(n, m)
        keys = [pub.generate_party(i) for i in range(n)]

        for i in range(n):
            for j in range(n):
                if i == j: continue
                keys[i].exchange(j, keys[j].get_exc_public_key())

        for i in range(n):
            keys[i].generate_share()

        mk = Palia.generate_query_key(pub)
        pk = mk.getPublicKey()
        enc_y = Palia.encrypt_query(y, pk, pub)

        cs = [Palia.encrypt(x[i], tag, keys[i]) for i in range(n)]
        sk = [Palia.keygen(enc_y, keys[i]) for i in range(n)]
        m = Palia.decrypt(cs, tag, pub, sk, y, mk, (0, 2000))
        end = time.time()
        logging.info(f'Palia test scheme 1 performance with Prime Group (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, m)

    def test_scheme_2(self):
        start = time.time()
        n = 5
        m = 5
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        tag = str(start).encode()
        pub = Palia.generate(n, m)
        keys = [pub.generate_party(i) for i in range(n)]

        for i in range(n):
            for j in range(n):
                if i == j: continue
                keys[i].exchange(j, keys[j].get_exc_public_key())

        for i in range(n):
            keys[i].generate_share()

        mk = Palia.generate_query_key(pub)
        pk = mk.getPublicKey()
        enc_y = Palia.encrypt_query(y, pk, pub)

        cs = [Palia.encrypt(x[i], tag, keys[i]) for i in range(n)]
        sk = [Palia.keygen(enc_y, keys[i]) for i in range(n)]
        res = Palia.decrypt(cs, tag, pub, sk, y, mk, (-10000000, 10000000))
        end = time.time()
        logging.info(f'Palia test scheme 2 performance with Prime Group (n={n},m={m}): {end - start}s')

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
        pub = Palia.generate(n, m, Curve25519)
        keys = [pub.generate_party(i) for i in range(n)]
        for i in range(n):
            for j in range(n):
                if i == j: continue
                keys[i].exchange(j, keys[j].get_exc_public_key())

        for i in range(n):
            keys[i].generate_share()

        mk = Palia.generate_query_key(pub)
        pk = mk.getPublicKey()
        enc_y = Palia.encrypt_query(y, pk, pub)

        cs = [Palia.encrypt(x[i], tag, keys[i]) for i in range(n)]
        sk = [Palia.keygen(enc_y, keys[i]) for i in range(n)]
        res = Palia.decrypt(cs, tag, pub, sk, y, mk, (-10000000, 10000000))
        end = time.time()

        logging.info(f'FeDDHMultiClient test scheme 3 performance with Curve25519 (n={n},m={m}): {end - start}s')

        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])

        self.assertEqual(expected, res)
