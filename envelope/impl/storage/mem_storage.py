import logging, time
from ndn.name_tree import NameTrie
import ndn.encoding as enc
import ndn.app_support.security_v2 as sv2

from ...storage import IteratableStorage, Box, Filter

class MemoryStorage(IteratableStorage):
    def __init__(self):
        self.data = NameTrie()

    async def search(self, name: enc.FormalName):
        """
        Search for the data packet that satisfying an Interest packet with name specified.

        :param name: the Interest name.
        :param param: the parameters of the Interest. Not used in current implementation.
        :return: a raw Data packet or None.
        """
        try:
            return next(self.data.itervalues(prefix=name, shallow=True))
        except KeyError:
            logging.debug(f'Cache miss: {enc.Name.to_str(name)}')
            return None

    async def iter(self, name: enc.FormalName):
        try:
            return [ item for item in next(self.data.itervalues(prefix=name))]
        except KeyError:
            logging.debug(f'Cache miss: {enc.Name.to_str(name)}')
            return None
        
    async def save(self, name: enc.FormalName, packet: enc.BinaryStr):
        """
        Save a Data packet with name into the memory storage.

        :param name: the Data name.
        :param packet: the raw Data packet.
        """
        logging.debug(f'Cache save: {enc.Name.to_str(name)}')
        self.data[name] = bytes(packet)

class MemoryBox(Box):
    def __init__(self):
        self.storage = MemoryStorage()
    def isIteratable(self):
        return isinstance(self.storage, IteratableStorage)

    async def get(self, prefix: enc.FormalName, filter: Filter):
        try:
            itervalues = await self.storage.iter(prefix)
            if itervalues is not None:
                for candidate in itervalues:
                    if await filter(candidate):
                        return candidate
                    else: continue
        except KeyError:
            logging.debug(f'Cache miss: {enc.Name.to_str(prefix)}')
            return None

    async def put(self, name: enc.FormalName, packet: enc.BinaryStr):
        logging.debug(f'Cache save: {enc.Name.to_str(name)}')
        self.storage.save(name, packet)