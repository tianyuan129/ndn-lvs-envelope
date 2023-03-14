import logging
from ndn.name_tree import NameTrie
import ndn.encoding as enc

from ...storage import Storage

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
