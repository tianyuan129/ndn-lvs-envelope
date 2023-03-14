import logging, os, sqlite3
import ndn.encoding as enc
from ndn.security.tpm import Tpm

from ...storage import Storage


INITIALIZE_SQL = """
CREATE TABLE IF NOT EXISTS
  certificates(
    certificate_name      BLOB PRIMARY KEY,
    certificate_data      BLOB NOT NULL
  );
CREATE UNIQUE INDEX IF NOT EXISTS
  certIndex ON certificates(certificate_name);
""" 

class Sqlite3Storage(Storage):
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
        self.conn = sqlite3.connect(path)

    async def search(self, name: enc.FormalName, param: enc.InterestParam):
        """
        Search for the data packet that satisfying an Interest packet with name specified.

        :param name: the Interest name.
        :param param: the parameters of the Interest. Not used in current implementation.
        :return: a raw Data packet or None.
        """
        if param is None or param.can_be_prefix == False:
            # treat as packet name
            name = enc.Name.to_bytes(name)
            sql = 'SELECT certificate_name, certificate_data FROM certificates WHERE certificate_name=?'
            cursor = self.conn.execute(sql, (name,))
            data = cursor.fetchone()
            if not data:
                logging.debug(f'Cache miss: {enc.Name.to_str(name)}')
                return
            cert_name, cert_data = data
            cursor.close()
            return cert_data
        else:
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