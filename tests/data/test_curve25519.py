from tests.test_base import TestBase
from src.mife.data.curve25519_y import Curve25519
from secrets import randbits


class TestFeDamgard(TestBase):
    def test_basics(self):
        g = Curve25519().generator()
        self.assertEqual(Curve25519.identity() + g, Curve25519.generator())

        ord = Curve25519.order()
        self.assertEqual(ord * g, Curve25519.identity())

