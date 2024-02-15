import logging

import ndn.encoding as enc
from ndn.app_support.security_v2 import KEY_COMPONENT
from ndn.name_tree import NameTrie
from ndn.app import NDNApp
from ndn.types import InterestNack, InterestTimeout, InterestParam

from ...storage import Box

class ExpressToNetworkBox(Box):
    def __init__(self, app: NDNApp):
        self.app = app
        self.data = NameTrie()
    def put(self, name: enc.FormalName, packet: enc.BinaryStr):
        self.data[name] = bytes(packet)
        # register to the network
        # quick check for certificate naming convention
        reg_name = name[:-3] if len(name) > 4 and name[-4] == KEY_COMPONENT else name
        @self.app.route(reg_name)
        def on_int(int_name: enc.FormalName, interest_param, _app_param):
            returned_packet = next(self.data.itervalues(prefix=int_name, shallow=True))
            if returned_packet:
                logging.info(f'ExpressToNetworkBox replied with: {enc.Name.to_str(name)}')
                self.app.put_raw_packet(returned_packet)
            else:
                logging.debug(f'ExpressToNetworkBox has no certificate for {enc.Name.to_str(int_name)}')

    async def get(self, name: enc.FormalName, **kwargs):
        interest_params = InterestParam()
        interest_params.can_be_prefix = False
        if 'interest_lifetime' in kwargs and kwargs['interest_lifetime']:
            interest_params.lifetime = kwargs['interest_lifetime']
        else: interest_params.lifetime = 1000
        if 'forwarding_hints' in kwargs and kwargs['forwarding_hints']:
            interest_params.forwarding_hint = kwargs['forwarding_hints']
        if 'retry' in kwargs and kwargs['retry']:
            retry_times = kwargs['retry']
        else: retry_times = 3
        trial_times = 0
        while True:
            trial_times += 1
            if trial_times > retry_times:
                break
            try:
                logging.info('Express Interest: {}'.format(enc.Name.to_str(name)))
                data_name, _, _, data_bytes = await self.app.express_interest(
                    name, interest_param=interest_params, need_raw_packet=True)
                # Save data and update final_id
                logging.info('Received data: {}'.format(enc.Name.to_str(data_name)))
                return data_bytes
            except InterestNack as e:
                logging.info(f'Nacked with reason={e.reason}')
            except InterestTimeout:
                logging.info(f'Timeout')