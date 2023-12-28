import abc
from typing import Optional
import ndn.encoding as enc

class TrustInfoBase(abc.ABC):
    @abc.abstractmethod
    def sign_data(self, name: enc.NonStrictName, meta_info: enc.MetaInfo,
                        content: Optional[enc.BinaryStr] = None) -> Optional[enc.VarBinaryStr]:
        pass

    @abc.abstractmethod
    def sign_cert(self, name: enc.NonStrictName, pub_key: enc.BinaryStr, start_time, expire_sec) -> Optional[enc.VarBinaryStr]:
        pass

    @abc.abstractmethod
    async def authenticate_data(self, name: enc.FormalName, sig_ptrs: enc.SignaturePtrs) -> bool:
        pass
