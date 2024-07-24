from secrets import token_bytes
from Crypto.Cipher import AES
from hashlib import sha256
from typing import List

class CPRF:
    def __init__(self, n: int):
        self.keys = None
        self.n = n

    def setup_key(self, security=128):
        self.keys = [[token_bytes(security // 8) for _ in range(i)] for i in range(self.n)]

    def keygen(self, i) -> List[bytes]:
        if self.keys is None:
            self.setup_key()

        keys = []
        for j in range(self.n):
            if j == i:
                keys.append(b'\x00')
            elif j < i:
                keys.append(self.keys[i][j])
            else:
                keys.append(self.keys[j][i])
        return keys

    @staticmethod
    def eval(n, i, keys: List[bytes], x: bytes, length: int):
        res = 0
        for j in range(n):
            if j == i:
                continue
            nonce = sha256(x).digest()
            cipher = AES.new(keys[j], AES.MODE_CTR, nonce=nonce[:8])
            prf_out = cipher.encrypt(b'\x00' * length)
            res += (-1)**(j < i) * int.from_bytes(prf_out, 'big')
        return res
