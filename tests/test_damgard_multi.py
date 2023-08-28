import unittest
from src.mife.damgard_multi import FeDamgardMulti


class TestFeDDH(unittest.TestCase):

    def test_scheme_1(self):
        n = 3
        m = 5
        bits = 512
        x = [[i + j for j in range(m)] for i in range(n)]
        y = [[i - j + 10 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m, bits)
        cs = [FeDamgardMulti.encrypt(x[i], i, key) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])
        m = FeDamgardMulti.decrypt(cs, key, sk, (0, 2000))
        self.assertEqual(expected, m)

    def test_scheme_2(self):
        n = 10
        m = 5
        bits = 512
        x = [[i * 10 + j for j in range(m)] for i in range(n)]
        y = [[i - j - 5 for j in range(m)] for i in range(n)]
        key = FeDamgardMulti.generate(n, m, bits)
        cs = [FeDamgardMulti.encrypt(x[i], i, key) for i in range(n)]
        sk = FeDamgardMulti.keygen(y, key)
        expected = 0
        for i in range(n):
            expected += sum([a * b for a, b in zip(x[i], y[i])])
        expected %= (key.p-1)
        m = FeDamgardMulti.decrypt(cs, key, sk, (-100000, 100000))
        self.assertEqual(expected, m)

