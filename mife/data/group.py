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
    def __call__(self, elem) -> GroupElem:
        """
        Convert an element to the group element

        :param elem:
        """
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

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __hash__(self):
        pass

    def __sub__(self, other):
        return self.__add__(other.__neg__())
