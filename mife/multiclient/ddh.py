from secrets import randbelow
from Crypto.Util.number import getStrongPrime, bytes_to_long
from typing import List, Tuple, Callable

from mife.common import discrete_log_bound, inner_product

from mife.data.group import GroupBase, GroupElem
from mife.data.zmod import Zmod

from hashlib import shake_256

# References:
# https://eprint.iacr.org/2017/989.pdf

class _FeDDHMultiClient_MK:
    def __init__(self, g: GroupElem, n: int, m: int, F: GroupBase,
                 hash: Callable[[bytes], Tuple[int, int]],
                 msk: List[List[Tuple[int, int]]] = None):
        """
        Initialize FeDDHMultiClient master key

        :param g: Generator of the group
        :param n: Number of clients
        :param m: Dimension of message vector for each client
        :param F: The Group
        :param hash: Hash function to use
        :param msk: Master secret key
        """
        self.g = g
        self.n = n
        self.m = m
        self.F = F
        self.hash = hash
        self.msk = msk

    def get_enc_key(self, index: int):
        """
        Get the encryption key for a client

        :param index: Index of the client
        :return: Encryption key for the client
        """
        if not self.has_private_key:
            raise Exception("The master key has no private key")
        if not (0 <= index < self.n):
            raise Exception(f"Index must be within [0,{self.n})")
        return _FeDDHMultiClient_EncK(self.g, self.hash, self.msk[index])

    def has_private_key(self) -> bool:
        return self.msk is not None

class _FeDDHMultiClient_EncK:
    def __init__(self, g: GroupElem,
                 hash: Callable[[bytes], Tuple[int, int]],
                 enc_key: List[Tuple[int, int]]):
        """
        Initialize FeDDHMultiClient encryption key

        :param g: Generator of the group
        :param hash: Hash function to use
        :param enc_key: Secret key shared with the client
        """
        self.g = g
        self.hash = hash
        self.enc_key = enc_key


class _FeDDHMultiClient_SK:
    def __init__(self, y: List[List[int]], d: Tuple[int, int]):
        """
        Initialize FeDDHMultiClient decryption key

        :param y: Function vector
        :param d: <msk, y>
        """
        self.y = y
        self.d = d

class _FeDDHMultiClient_C:
    def __init__(self, c: List[GroupElem]):
        """
        Initialize FeDDHMultiClient cipher text

        :param c: (<h(tag), s[i]> + x[i]) * g
        """
        self.c = c

class FeDDHMultiClient:

    @staticmethod
    def default_hash(tag: bytes, maximum_bit: int) -> Tuple[int, int]:
        """
        Default hash H : tag -> Z_p x Z_p with shake_256

        :param tag:
        :param maximum_bit:
        :return: (u1, u2) with u1, u2 < 2^maximum_bit
        """
        t = shake_256(tag).digest(maximum_bit * 2)
        return bytes_to_long(t[:len(t)//2]), bytes_to_long(t[len(t)//2:])

    @staticmethod
    def generate(n: int, m: int, F: GroupBase = None,
                 hash: Callable[[bytes, int], Tuple[int, int]] = None) -> _FeDDHMultiClient_MK:
        """
        Generate a FeDDHMultiClient master key

        :param n: Number of clients
        :param m: Dimension of message vector for each client
        :param F: Group to use for the scheme. If set to None, a random 1024 bit prime group will be used
        :param hash: Hash function to use. If set to None, a default hash function will be used
        :return: FeDDHMultiClient master key
        """
        if F is None:
            F = Zmod(getStrongPrime(1024))
        if hash is None:
            hash = lambda x: FeDDHMultiClient.default_hash(x, F.order().bit_length())

        g = F.generator()
        s = [[(randbelow(F.order()), randbelow(F.order())) for _ in range(m)] for _ in range(n)]

        return _FeDDHMultiClient_MK(g, n, m, F, hash, msk=s)

    @staticmethod
    def encrypt(x: List[int], tag: bytes, key: _FeDDHMultiClient_EncK) -> _FeDDHMultiClient_C:
        """
        Encrypt message vector

        :param x: Message vector
        :param tag: Tag for the encryption, usually time stamp
        :param key: Client encryption key
        :return: FeDDHMultiClient cipher text
        """
        if len(x) != len(key.enc_key):
            raise Exception(f"Encrypt vector must be of length {len(key.enc_key)}")

        u1, u2 = key.hash(tag)

        c = []

        for i in range(len(x)):
            s1, s2 = key.enc_key[i]
            c.append((u1 * s1 + u2 * s2 + x[i]) * key.g)

        return _FeDDHMultiClient_C(c)

    @staticmethod
    def decrypt(c: List[_FeDDHMultiClient_C], tag: bytes,
                key: _FeDDHMultiClient_MK, sk: _FeDDHMultiClient_SK,
                bound: Tuple[int, int]) -> int:
        """
        Decrypt FeDDHMultiClient cipher text

        :param c: FeDDHMultiClient cipher text
        :param tag: Tag for decryption, the same tag must be used for encryption
        :param key: FeDDHMultiClient public key
        :param sk: FeDDHMultiClient decryption key
        :param bound: Bound for the discrete log problem
        :return: Decrypted message
        """
        u1, u2 = key.hash(tag)
        u1, u2 = key.g * u1, key.g * u2

        cul = key.F.identity()

        for i in range(key.n):
            cul = cul + inner_product(c[i].c, sk.y[i], key.F.identity())

        cul = cul - (sk.d[0] * u1 + sk.d[1] * u2)
        return discrete_log_bound(cul, key.g, bound)

    @staticmethod
    def keygen(y: List[List[int]], key: _FeDDHMultiClient_MK) -> _FeDDHMultiClient_SK:
        """
        Generate a FeDDHMultiClient decryption key

        :param y: Function vector
        :param key: FeDDHMultiClient master key
        :return: FeDDHMultiClient decryption key
        """
        if len(y) != key.n:
            raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
        cul_1 = 0
        cul_2 = 0
        for i in range(key.n):
            if len(y[i]) != key.m:
                raise Exception(f"Function vector must be a {key.n} x {key.m} matrix")
            for j in range(key.m):
                s1, s2 = key.msk[i][j]
                cul_1 += s1 * y[i][j]
                cul_2 += s2 * y[i][j]

        d = (cul_1, cul_2)
        return _FeDDHMultiClient_SK(y, d)
