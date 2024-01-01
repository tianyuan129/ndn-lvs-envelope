import abc
from typing import Optional, Callable, Any, Coroutine, List
import ndn.encoding as enc

Filter = Callable[[enc.BinaryStr, Any], Coroutine[Any, None, bool]]

class Storage(abc.ABC):
    @abc.abstractmethod
    async def search(self, name: enc.FormalName) -> bytes:
        pass

    @abc.abstractmethod
    async def save(self, name: enc.FormalName, packet: enc.BinaryStr):
        pass

class IteratableStorage(Storage):
    @abc.abstractmethod
    async def iter(self, prefix: enc.FormalName) -> List[bytes]:
        pass

class Box(abc.ABC):
    @abc.abstractmethod
    async def get(self, prefix: enc.FormalName):
        pass

    @abc.abstractmethod
    async def put(self, name: enc.FormalName, packet: enc.BinaryStr):
        pass

class SearchableBox(Box):
    @abc.abstractmethod
    async def search(self, prefix: enc.FormalName, filter: Filter):
        pass