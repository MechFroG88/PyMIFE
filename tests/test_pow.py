import time
import logging
from tests.test_base import TestBase
from Crypto.Util.number import getStrongPrime
from secrets import randbelow
from gmpy2 import powmod

class TestPow(TestBase):

    def test_pow(self):
        p = getStrongPrime(512)
        g = 2
        exp = [randbelow(p) for _ in range(10)]
        start1 = time.time()
        [powmod(g, e, p) for e in exp]
        end1 = time.time()
        start2 = time.time()
        [pow(g, e, p) for e in exp]
        end2 = time.time()

        logging.info(f'gmpy2 : {end1 - start1}s')
        logging.info(f'python pow : {end2 - start2}s')
