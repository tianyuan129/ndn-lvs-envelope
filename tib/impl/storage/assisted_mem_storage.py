import logging
import ndn.encoding as enc
from ndn.types import InterestNack, InterestTimeout
from ndn.app import NDNApp

from ...storage import Storage
from .mem_storage import MemoryStorage

class AssistedMemoryStorage(Storage):
    def __init__(self, app: NDNApp):
        self.storage = MemoryStorage()
        self.app = app

    async def search(self, name: enc.FormalName, param: enc.InterestParam):
        """
        Search for the data packet that satisfying an Interest packet with name specified.

        :param name: the Interest name.
        :param param: the parameters of the Interest. Not used in current implementation.
        :return: a raw Data packet or None.
        """
        local = await self.storage.search(name, param)
        if local is not None:
            return local
        else:
            trial_times = 0
            while True:
                trial_times += 1
                if trial_times > 3:
                    break
                try:
                    logging.info('Express Interest: {}'.format(enc.Name.to_str(name)))
                    data_name, _, _, data_bytes = await self.app.express_interest(
                        name, need_raw_packet=True, can_be_prefix=False, lifetime=1000)
                    # Save data and update final_id
                    logging.info('Received data: {}'.format(enc.Name.to_str(data_name)))
                    await self.storage.save(name, data_bytes)
                    return data_bytes
                except InterestNack as e:
                    logging.info(f'Nacked with reason={e.reason}')
                except InterestTimeout:
                    logging.info(f'Timeout')

    async def save(self, name: enc.FormalName, packet: enc.BinaryStr):
        """
        Save a Data packet with name into the memory storage.

        :param name: the Data name.
        :param packet: the raw Data packet.
        """
        await self.storage.save(name, packet)
