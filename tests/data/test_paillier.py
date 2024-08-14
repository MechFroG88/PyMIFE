from tests.test_base import TestBase
from mife.data.paillier import Paillier
import time, logging

class TestPaillier(TestBase):

    p = 134571773007924833854065458592286178876746744565913736881821465801779595071970858872308614994816317338556606169429905285264914998387968583302245087560224843241552942789674059901173947740579704064275315217146295711314307876927426902112041290244046572242022612528256950525807940730241959500337908782397375334067
    q = 136376041929080745332720207555608615396952127278171064896949721772485191795889286118100472072063058684610764963190170043115874503100144966915460078488572507709185072831129777110117660963433630166361483550907430003279041723670193111462964773640424026516757060999870723874192759460049941352318214316748147414927

    def test_basic(self):
        start1 = time.time()
        sk = Paillier.generate(1024, TestPaillier.p, TestPaillier.q)
        pk = sk.getPublicKey()

        c = pk.encrypt(3000)
        m = sk.decrypt(c)

        self.assertEqual(3000, m)
        end1 = time.time()

        logging.info(f'Paillier Basic : {end1 - start1}s')

    def test_homomorphic_add(self):
        start1 = time.time()
        sk = Paillier.generate(1024, TestPaillier.p, TestPaillier.q)
        pk = sk.getPublicKey()

        c1 = pk.encrypt(3000)

        c2 = pk.encrypt(2000)
        c3 = c1 + c2

        m = sk.decrypt(c3)
        self.assertEqual(m, 5000)
        end1 = time.time()

        logging.info(f'Paillier Homomorphic Add : {end1 - start1}s')

    def test_homomorphic_mul(self):
        start1 = time.time()
        sk = Paillier.generate(1024, TestPaillier.p, TestPaillier.q)
        pk = sk.getPublicKey()

        c1 = pk.encrypt(3000)
        c2 = 3 * c1

        m = sk.decrypt(c2)
        self.assertEqual(m, 9000)
        end1 = time.time()

        logging.info(f'Paillier Homomorphic Mul : {end1 - start1}s')

    def test_homomorphic_1(self):
        start1 = time.time()
        sk = Paillier.generate(1024, TestPaillier.p, TestPaillier.q)
        pk = sk.getPublicKey()

        c1 = pk.encrypt(1000)
        c2 = pk.encrypt(4000)

        c3 = 3 * c1 + 2 * c2

        m = sk.decrypt(c3)
        self.assertEqual(m, 11000)

        end1 = time.time()

        logging.info(f'Paillier Homomorphic 1 : {end1 - start1}s')

    def test_homomorphic_2(self):
        start1 = time.time()
        sk = Paillier.generate(1024, TestPaillier.p, TestPaillier.q)
        pk = sk.getPublicKey()

        c1 = pk.encrypt(1000)
        c2 = pk.encrypt(4000)

        c3 = 0
        c3 += 3 * c1
        c3 += 2 * c2

        m = sk.decrypt(c3)
        self.assertEqual(m, 11000)

        end1 = time.time()

        logging.info(f'Paillier Homomorphic 2 : {end1 - start1}s')