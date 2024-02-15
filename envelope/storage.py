import abc
from typing import Callable, Any, Coroutine, List
import ndn.encoding as enc

Filter = Callable[[enc.BinaryStr, Any], Coroutine[Any, None, bool]]

class Box(abc.ABC):
    @abc.abstractmethod
    async def get(self, prefix: enc.FormalName):
        pass

class SearchableBox(Box):
    @abc.abstractmethod
    async def search(self, prefix: enc.FormalName, filter: Filter):
        pass