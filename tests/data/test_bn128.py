from tests.test_base import TestBase
from mife.data.pyecc_bn128_wrapper import Bn128Pairing
import time, logging

class TestBn128(TestBase):
    def test_basics(self):

        G = Bn128Pairing()
        g1 = G.generator1()
        g2 = G.generator2()
        gT = G.generatorT()

        start1 = time.time()
        self.assertEqual(G.pairing(g1 + g1, 3 * g2), (4 * gT) + (3 * gT) - (1 * gT))
        end1 = time.time()

        logging.info(f'Bn128 Pairing Basic 1 : {end1 - start1}s')

    def test_basics_2(self):
        G = Bn128Pairing()
        g1 = G.generator1()
        g2 = G.generator2()
        gT = G.generatorT()

        start1 = time.time()
        self.assertEqual(G.pairing(g1, g2), gT)
        end1 = time.time()

        logging.info(f'Bn128 Pairing Basic 2 : {end1 - start1}s')
