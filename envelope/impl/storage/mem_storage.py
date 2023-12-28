import logging, time
from ndn.name_tree import NameTrie
import ndn.encoding as enc
import ndn.app_support.security_v2 as sv2

from ...storage import Storage, Box, Filter

class MemoryStorage(Storage):
    def __init__(self):
        self.data = NameTrie()

    async def search(self, name: enc.FormalName, param: enc.InterestParam):
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
        self.data = NameTrie()

    async def get(self, prefix: enc.FormalName, filter: Filter):
        try:
            candidates = self.data.itervalues(prefix=prefix, shallow=True)
            next_cert = next(candidates)
            while filter and not await filter(next_cert):
                next_cert = next(candidates)
            return next_cert
        except KeyError:
            logging.debug(f'Cache miss: {enc.Name.to_str(prefix)}')
            return None

    async def put(self, name: enc.FormalName, packet: enc.BinaryStr):
        logging.debug(f'Cache save: {enc.Name.to_str(name)}')
        self.data[name] = bytes(packet)