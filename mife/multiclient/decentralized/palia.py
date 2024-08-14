from __future__ import annotations

from typing import List, Tuple, Callable

from mife.data.group import GroupBase
from mife.data.paillier import PaillierKey, PaillierElem, Paillier
from mife.multiclient.decentralized.ddh import (FeDDHMultiClientDec, _FeDDHMultiClientDec_PK,
                                                _FeDDHMultiClientDec_C, _FeDDHMultiClientDec_MK,
                                                _FeDDHMultiClientDec_SK)
class Palia:
    @staticmethod
    def generate(n: int, m: int, F: GroupBase = None,
                 hash: Callable[[bytes, int], Tuple[int, int]] = None) -> _FeDDHMultiClientDec_PK:
        return FeDDHMultiClientDec.generate(n, m, F, hash)

    @staticmethod
    def encrypt(x: List[int], tag: bytes, key: _FeDDHMultiClientDec_MK) -> _FeDDHMultiClientDec_C:
        return FeDDHMultiClientDec.encrypt(x, tag, key)

    @staticmethod
    def decrypt(c: List[_FeDDHMultiClientDec_C], tag: bytes,
                key: _FeDDHMultiClientDec_PK, sk: List[_FeDDHMultiClientDec_SK], y: List[List[int]], mk: PaillierKey,
                bound: Tuple[int, int]) -> int:
        dec_sk = [_FeDDHMultiClientDec_SK(y, (mk.decrypt(sk[i].d[0]), mk.decrypt(sk[i].d[1]))) for i in range(len(sk))]
        return FeDDHMultiClientDec.decrypt(c, tag, key, dec_sk, bound)

    @staticmethod
    def keygen(enc_y: List[List[PaillierElem]], key: _FeDDHMultiClientDec_MK) -> _FeDDHMultiClientDec_SK:
        return FeDDHMultiClientDec.keygen(enc_y, key)

    @staticmethod
    def encrypt_query(y: List[List[int]], pk: PaillierKey, pub: _FeDDHMultiClientDec_PK) -> List[List[PaillierElem]]:
        return [[pk.encrypt(y[i][j] % pub.F.order()) for j in range(len(y[i]))] for i in range(len(y))]

    @staticmethod
    def generate_query_key(pub: _FeDDHMultiClientDec_PK) -> PaillierKey:
        bitsize = ((pub.F.order().bit_length() + (pub.n * pub.m).bit_length() + 127) // 128) * 128
        bitsize = max(512, bitsize)
        return Paillier.generate(bitsize)