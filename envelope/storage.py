import abc
from typing import Optional, Callable, Any, Coroutine
import ndn.encoding as enc

Filter = Callable[[enc.BinaryStr, Any], Coroutine[Any, None, bool]]

class Storage(abc.ABC):
    @abc.abstractmethod
    async def search(self, name: enc.FormalName, param: enc.InterestParam):
        pass

    @abc.abstractmethod
    async def save(self, name: enc.FormalName, packet: enc.BinaryStr):
        pass

class Box(abc.ABC):
    @abc.abstractmethod
    async def get(self, prefix: enc.FormalName, filter: Filter):
        pass

    @abc.abstractmethod
    async def put(self, name: enc.FormalName, packet: enc.BinaryStr):
        pass