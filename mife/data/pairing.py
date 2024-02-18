from __future__ import annotations

from abc import ABC, abstractmethod
from mife.data.group import GroupElem


class PairingBase(ABC):

    @abstractmethod
    def order(self) -> int:
        pass

    @abstractmethod
    def identity1(self) -> GroupElem:
        pass

    @abstractmethod
    def identity2(self) -> GroupElem:
        pass

    @abstractmethod
    def identityT(self) -> GroupElem:
        pass

    @abstractmethod
    def generator1(self) -> GroupElem:
        pass

    @abstractmethod
    def generator2(self) -> GroupElem:
        pass

    @abstractmethod
    def generatorT(self) -> GroupElem:
        pass

    @abstractmethod
    def pairing(self, g1: GroupElem, g2: GroupElem) -> GroupElem:
        pass
