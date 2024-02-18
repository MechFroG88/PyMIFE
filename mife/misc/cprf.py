from secrets import token_bytes
import random
import hmac
from typing import List

class CPRF:
    def __init__(self, n: int, p: int, ):
        self.keys = None
        self.n = n
        self.p = p

    def setup_key(self, security=128):
        self.keys = [[token_bytes(security // 8) for _ in range(i)] for i in range(self.n)]

    def keygen(self, i):
        if self.keys is None:
            self.setup_key()

        keys = []
        for j in range(self.n):
            if j == i:
                keys.append(0)
            elif j < i:
                keys.append(self.keys[i][j])
            else:
                keys.append(self.keys[j][i])
        return keys

    def eval(self, i, keys: List[bytes], x):
        res = 0
        t = self.p.bit_length()
        for j in range(self.n):
            if j == i:
                continue
            seed = hmac.digest(keys[j], x, "sha256")
            random.seed(seed)
            res += (-1)**(j < i) * random.getrandbits(t)
            res %= self.p
        return res
