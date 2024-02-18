import unittest
import logging
from mife.misc.cprf import CPRF
from Crypto.Util.number import getPrime

class TestCPRF(unittest.TestCase):
    logging.getLogger().setLevel(logging.INFO)

    def test_cprf_1(self):
        n = 3
        p = getPrime(512)
        cprf = CPRF(n, p)
        cprf.setup_key()
        keys = [cprf.keygen(i) for i in range(n)]
        x = b'hello'
        res = [cprf.eval(i, keys[i], x) for i in range(n)]
        assert sum(res) % p == 0

    def test_cprf_2(self):
        n = 10
        p = getPrime(512)
        cprf = CPRF(n, p)
        cprf.setup_key()
        keys = [cprf.keygen(i) for i in range(n)]
        x = b'123456'
        res = [cprf.eval(i, keys[i], x) for i in range(n)]
        assert sum(res) % p == 0
