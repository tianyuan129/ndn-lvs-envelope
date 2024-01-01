import logging, os, sqlite3
import ndn.encoding as enc
from typing import List

from ...storage import IteratableStorage, Box, Filter

INITIALIZE_SQL = """
CREATE TABLE IF NOT EXISTS
  certificates(
    certificate_name      BLOB PRIMARY KEY,
    certificate_data      BLOB NOT NULL
  );
CREATE UNIQUE INDEX IF NOT EXISTS
  certIndex ON certificates(certificate_name);
""" 

class Sqlite3Storage(IteratableStorage):
    @staticmethod
    def initialize(path: str) -> bool:
        if os.path.exists(path):
            logging.fatal(f'Database {path} already exists.')
            return False
        # Make sure the directory exists
        base_dir = os.path.dirname(path)
        os.makedirs(base_dir, exist_ok=True)
        # Create sqlite3 database
        conn = sqlite3.connect(path)
        conn.executescript(INITIALIZE_SQL)
        conn.commit()
        conn.close()
        return True

    def __init__(self, path: str):
        self.path = path
        # cross-finger and pray
        self.conn = sqlite3.connect(path, check_same_thread=False)

    async def search(self, name: enc.FormalName):
        """
        Search for the data packet that satisfying an Interest packet with name specified.

        :param name: the Interest name.
        :param param: the parameters of the Interest. Not used in current implementation.
        :return: a raw Data packet or None.
        """
        cursor = self.conn.execute('SELECT certificate_name, certificate_data FROM certificates')
        data = cursor.fetchall()
        if not data:
            logging.debug(f'Cache miss: {enc.Name.to_str(name)}')
            return
        for entry in data:
            entry_name, entry_data = entry
            logging.debug(f'checking cert: {enc.Name.to_str(entry_name)}')
            if enc.Name.is_prefix(name, entry_name):
                logging.debug(f'getting cert: {enc.Name.to_str(entry_name)}')
                cursor.close()
                return entry_data

    async def save(self, name: enc.FormalName, packet: enc.BinaryStr):
        """
        Save a Data packet with name into the memory storage.

        :param name: the Data name.
        :param packet: the raw Data packet.
        """
        try:
            self.conn.execute('INSERT INTO certificates (certificate_name, certificate_data)'
                            'VALUES (?, ?)',
                            (enc.Name.to_bytes(name), bytes(packet)))
            self.conn.commit()
        except sqlite3.IntegrityError:
            logging.debug(f'Certificate already exist: {enc.Name.to_str(name)}')

    async def iter(self, prefix: enc.FormalName) -> List[bytes]:
        """
        Search for the data packet that satisfying an Interest packet with name specified.

        :param name: the Interest name.
        :param param: the parameters of the Interest. Not used in current implementation.
        :return: a raw Data packet or None.
        """
        cursor = self.conn.execute('SELECT certificate_name, certificate_data FROM certificates')
        data = cursor.fetchall()
        if not data:
            logging.debug(f'Cache miss: {enc.Name.to_str(prefix)}')
            return
        ret = []
        for entry in data:
            entry_name, entry_data = entry
            logging.debug(f'checking cert: {enc.Name.to_str(entry_name)}')
            if enc.Name.is_prefix(prefix, entry_name):
                logging.debug(f'getting cert: {enc.Name.to_str(entry_name)}')
                ret.append(entry_data)
        return ret

class Sqlite3Box(Box):
    def __init__(self, path: str, initialize = False):
        if initialize:
            Sqlite3Storage.initialize(path)
        self.storage = Sqlite3Storage(path)
    def isIteratable(self):
        return isinstance(self.storage, IteratableStorage)

    async def get(self, prefix: enc.FormalName, filter: Filter):
        """
        Search for the data packet that satisfying an Interest packet with name specified.

        :param name: the Interest name.
        :param param: the parameters of the Interest. Not used in current implementation.
        :return: a raw Data packet or None.
        """
        itervalues = await self.storage.iter(prefix)
        if itervalues is not None:
            for item in itervalues:
                if await filter(item):
                    return item
        return None

    async def put(self, name: enc.FormalName, packet: enc.BinaryStr):
        """
        Save a Data packet with name into the memory storage.

        :param name: the Data name.
        :param packet: the raw Data packet.
        """
        await self.storage.save(name, packet)