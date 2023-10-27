from __future__ import annotations

from abc import ABC, abstractmethod

class GroupBase(ABC):

    @abstractmethod
    def order(self) -> int:
        pass

    @abstractmethod
    def identity(self) -> GroupElem:
        pass

    @abstractmethod
    def generator(self) -> GroupElem:
        pass

    @abstractmethod
    def export(self) -> dict:
        # Export the group object details as dictionary for export
        pass


class GroupElem(ABC):
    @abstractmethod
    def __add__(self, other):
        pass

    @abstractmethod
    def __neg__(self):
        pass

    @abstractmethod
    def __rmul__(self, other):
        pass

    def __mul__(self, other):
        if isinstance(other, int) or isinstance(other, mpz):
            return self.__rmul__(other)
        raise f"Unsupported multiplication between {type(self)}, {type(other)}"

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __hash__(self):
        pass

    def __sub__(self, other):
        return self.__add__(other.__neg__())

    @abstractmethod
    def export(self) -> dict:
        # Export the group object details as dictionary for export
        pass
