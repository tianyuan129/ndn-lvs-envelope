import abc
from typing import Optional, Tuple
import ndn.encoding as enc
from .storage import Box

class EnvelopeBase(abc.ABC):
    @abc.abstractmethod
    def sign_data(self, name: enc.NonStrictName, meta_info: enc.MetaInfo,
                  content: Optional[enc.BinaryStr] = None) -> Optional[enc.VarBinaryStr]:
        pass

    @abc.abstractmethod
    def sign_interest(self, name: enc.NonStrictName, interest_param: enc.InterestParam, app_param: Optional[enc.BinaryStr] = None) -> Optional[Tuple[enc.FormalName, enc.VarBinaryStr]]:
        pass

    @abc.abstractmethod
    def sign_cert(self, name: enc.NonStrictName, pub_key: enc.BinaryStr, start_time, expire_sec) -> Optional[enc.VarBinaryStr]:
        pass

    @abc.abstractmethod
    async def validate(self, name: enc.FormalName, sig_ptrs: enc.SignaturePtrs) -> bool:
        pass
