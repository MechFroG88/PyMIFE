import unittest
import logging
from mife.misc.cprf import CPRF
from Crypto.Util.number import getPrime

class TestCPRF(unittest.TestCase):
    logging.getLogger().setLevel(logging.INFO)

    def test_cprf_1(self):
        n = 3
        cprf = CPRF(n)
        cprf.setup_key()
        keys = [cprf.keygen(i) for i in range(n)]
        x = b'hello'
        res = [cprf.eval(n, i, keys[i], x, 512) for i in range(n)]
        assert sum(res) == 0

    def test_cprf_2(self):
        n = 10
        cprf = CPRF(n)
        cprf.setup_key()
        keys = [cprf.keygen(i) for i in range(n)]
        x = b'123456'
        res = [cprf.eval(n, i, keys[i], x, 512) for i in range(n)]
        assert sum(res) == 0
