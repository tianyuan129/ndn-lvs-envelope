import os, logging
import asyncio as aio
from typing import Optional
from hashlib import sha256

import ndn.encoding as enc
from ndn.app import NDNApp
from ndn.types import InterestNack, InterestTimeout
from ndn.utils import gen_nonce

from ndn_python_repo.clients.command_checker import CommandChecker
from ndn_python_repo.command.repo_commands import RepoCommandParameter, ForwardingHint,\
                                                  RegisterPrefix, CheckPrefix
from ndn_python_repo.utils import PubSub

from ...storage import Storage, Box, Filter

class RepoV3Storage(Storage):
    def __init__(self, app: NDNApp, prefix: enc.NonStrictName, repo_name: enc.NonStrictName,
                 forwarding_hint: Optional[enc.NonStrictName] = None):
        self.app = app
        self.prefix = prefix
        self.repo_name = enc.Name.normalize(repo_name)
        self.ready_packets = {}
        self.pb = PubSub(self.app, enc.Name.normalize(self.prefix))
        self.pb.base_prefix = self.prefix
        self.forwarding_hint = forwarding_hint

    def _on_interest(self, int_name, _int_param, _app_param):
        # use segment number to index into the encoded packets array
        logging.info(f'On interest: {enc.Name.to_str(int_name)}')
        name = enc.Name.to_bytes(int_name)
        if name in self.ready_packets:
            self.app.put_raw_packet(self.ready_packets[name])
            logging.info(f'Serve data: {enc.Name.to_str(int_name)}')
        else:
            logging.info(f'Data does not exist: {enc.Name.to_str(int_name)}')

    async def insert_data(self, data_name: enc.FormalName, data_bytes: enc.BinaryStr,
                          check_prefix: Optional[enc.NonStrictName] = None):
        self.ready_packets[enc.Name.to_bytes(data_name)] = data_bytes
        # If the uploaded file has the client's name as prefix, set an interest filter
        # for handling corresponding Interests from the repo
        if enc.Name.is_prefix(self.prefix, data_name):
            self.app.set_interest_filter(data_name, self._on_interest)
        else:
            # Otherwise, register the file name as prefix for responding interests from the repo
            logging.info(f'Register prefix for data upload: {enc.Name.to_str(data_name)}')
            try:
                await self.app.register(data_name, self._on_interest)
            except ValueError:
                logging.info(f'Duplicate insertion: {enc.Name.to_str(data_name)}')
                return

        # construct insert cmd msg
        cmd_param = RepoCommandParameter()
        cmd_param.name = data_name
        cmd_param.forwarding_hint = ForwardingHint()
        cmd_param.forwarding_hint.name = self.forwarding_hint
        process_id = gen_nonce()
        cmd_param.process_id = process_id.to_bytes(4, 'big')
        # cmd_param.register_prefix = RegisterPrefix()
        # cmd_param.register_prefix.name = data_name
        if check_prefix == None:
            check_prefix = self.prefix
        cmd_param.check_prefix = CheckPrefix()
        cmd_param.check_prefix.name = check_prefix
        cmd_param_bytes = cmd_param.encode()

        # publish msg to repo's insert topic
        await self.pb.wait_for_ready()
        is_success = await self.pb.publish(self.repo_name + enc.Name.from_str('insert'), cmd_param_bytes)
        if is_success:
            logging.info('Published an insert msg and was acknowledged by a subscriber')
        else:
            logging.info('Published an insert msg but was not acknowledged by a subscriber')
        # wait until finish so that repo can finish fetching the data
        if is_success:
            return await self._wait_for_finish(check_prefix, process_id)

    async def _wait_for_finish(self, check_prefix: enc.NonStrictName, process_id: int) -> int:
        """
        Wait until process `process_id` completes by sending check interests.
        :param check_prefix: NonStrictName. The prefix under which the check message will be\
            published.
        :param process_id: int. The process id to check.
        :return: number of inserted packets.
        """
        checker = CommandChecker(self.app)
        n_retries = 5
        while n_retries > 0:
            response = await checker.check_insert(self.repo_name, process_id.to_bytes(4, 'big'))
            if response is None:
                logging.info(f'Response code is None')
                n_retries -= 1
                await aio.sleep(1)
            # might receive 404 if repo has not yet processed insert command msg
            logging.info('Insert process {} status: {}, insert_num: {}'
                            .format(process_id,
                                    response.status_code,
                                    response.insert_num))
            return response.insert_num

    async def search(self, name: enc.FormalName, param: enc.InterestParam):
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
                return data_bytes
            except InterestNack as e:
                logging.info(f'Nacked with reason={e.reason}')
            except InterestTimeout:
                logging.info(f'Timeout')

    async def save(self, name: enc.FormalName, packet: enc.BinaryStr):
        await self.insert_data(name, packet)

class RepoV3Box(Box):
    def __init__(self, app: NDNApp, prefix: enc.NonStrictName, repo_name: enc.NonStrictName,
                 forwarding_hint: Optional[enc.NonStrictName] = None):
        self.storage = RepoV3Storage(app, prefix, repo_name, forwarding_hint)

    def isIteratable(self):
        return isinstance(self.storage, IteratableStorage)
    
    async def _get_runner(self, name):
        trial_times = 0
        while True:
            trial_times += 1
            if trial_times > 3:
                break
            try:
                logging.info('Express Interest: {}'.format(enc.Name.to_str(name)))
                data_name, _, _, data_bytes = await self.storage.app.express_interest(
                    name, need_raw_packet=True, can_be_prefix=True, lifetime=1000,
                    forwarding_hint = [self.storage.repo_name])
                # Save data and update final_id
                logging.info('Received data: {}'.format(enc.Name.to_str(data_name)))
                return data_bytes
            except InterestNack as e:
                logging.info(f'Nacked with reason={e.reason}')
            except InterestTimeout:
                logging.info(f'Timeout')
    async def get(self, prefix: enc.FormalName, filter: Filter):
        packet = await self._get_runner(prefix)
        return packet if await filter(packet) else None

    async def put(self, name: enc.FormalName, packet: enc.BinaryStr):
        await self.storage.insert_data(name, packet)