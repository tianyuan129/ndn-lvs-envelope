import logging
from ndn.name_tree import NameTrie
import ndn.encoding as enc

from ...storage import SearchableBox, Filter

class MemoryBox(SearchableBox):
    def __init__(self):
        self.data = NameTrie()
    
    async def get(self, name: enc.FormalName):
        try:
            return next(self.data.itervalues(prefix=name, shallow=True))
        except KeyError:
            logging.debug(f'Cache miss: {enc.Name.to_str(name)}')
            return None

    async def search(self, prefix: enc.FormalName, filter: Filter):
        try:
            itervalues = self.data.itervalues(prefix)
            if itervalues is not None:
                for candidate in itervalues:
                    if await filter(candidate):
                        return candidate
                    else: continue
        except KeyError:
            logging.debug(f'Cache miss: {enc.Name.to_str(prefix)}')
            return None

    def put(self, name: enc.FormalName, packet: enc.BinaryStr):
        self.data[name] = bytes(packet)