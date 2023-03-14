import abc
import ndn.encoding as enc

class Storage(abc.ABC):
    @abc.abstractmethod
    async def search(self, name: enc.FormalName, param: enc.InterestParam):
        pass

    @abc.abstractmethod
    async def save(self, name: enc.FormalName, packet: enc.BinaryStr):
        pass