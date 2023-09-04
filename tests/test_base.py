import unittest
import logging


class TestBase(unittest.TestCase):
    logging.getLogger().setLevel(logging.INFO)
