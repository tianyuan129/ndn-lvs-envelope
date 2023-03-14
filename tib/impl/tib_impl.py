import logging
from typing import Dict, Optional, Any, Tuple
from ndn.app import NDNApp, Validator
from ndn.security.tpm import Tpm
import ndn.encoding as enc
import ndn.app_support.security_v2 as sv2
import ndn.app_support.light_versec.binary as bny
import ndn.app_support.light_versec.checker as chk

from ..tib import TrustInfoBase
from ..annot_model import AnnotLvsModel
from ..storage import Storage
from .checker.cascade_checker import make_validator

class TrustInfoBaseImpl(TrustInfoBase):
    app: NDNApp
    annot_model: AnnotLvsModel
    cert_storage: Storage
    anchor_name: enc.FormalName
    tpm: Tpm
    authenticator: Validator
    def __init__(self, app: NDNApp, data_storage: Storage, tpm: Tpm):
        self.app = app
        self.cert_storage = data_storage
        self.tpm = tpm

    async def set(self, trust_anchor: enc.BinaryStr, model: bny.LvsModel, usr_func: Dict = chk.DEFAULT_USER_FNS):
        self.anchor_name = sv2.parse_certificate(trust_anchor).name
        await self.cert_storage.save(self.anchor_name, trust_anchor)
        self.annot_model = AnnotLvsModel(model)
        self.authenticator = make_validator(chk.Checker(model, usr_func), 
                                            self.app, trust_anchor, storage = self.cert_storage)

    def add_key(self, id: enc.NonStrictName, key_type: str = 'rsa', **kwargs: Any) -> Tuple[enc.FormalName, enc.BinaryStr]:
        return self.tpm.generate_key(enc.Name.normalize(id), key_type, **kwargs)
    
    async def add_certificate(self, cert: enc.BinaryStr):
        cert_name = sv2.parse_certificate(cert).name
        self.annot_model.annotate(cert_name)
        await self.cert_storage.save(cert_name, cert)

    def sign_data(self, name: enc.NonStrictName, meta_info: enc.MetaInfo,
                        content: Optional[enc.BinaryStr] = None) -> Optional[enc.VarBinaryStr]:
        key_locators = self.annot_model.locate_certs(enc.Name.normalize(name))
        for key_locator in key_locators:
            try:
                signer = self.tpm.get_signer(key_locator[:-2], key_locator)
            except:
                continue
            else:
                return enc.make_data(name, meta_info, content, signer)
        logging.debug(f'No suitable key locators for {enc.Name.to_str(name)} ...')

    def sign_cert(self, name: enc.NonStrictName, meta_info: enc.MetaInfo, pub_key: enc.BinaryStr, start_time, end_time) -> Optional[enc.VarBinaryStr]:
        # prepare name, metainfo, content and signaure info
        cert_val = sv2.CertificateV2Value()
        cert_val.name = name
        cert_val.content = pub_key
        cert_val.meta_info = meta_info
        cert_val.signature_info = sv2.CertificateV2SignatureInfo()
        cert_val.signature_info.validity_period = sv2.ValidityPeriod()
        cur_time = start_time
        not_before = cur_time.strftime('%Y%m%dT%H%M%S').encode()
        cert_val.signature_info.validity_period.not_before = not_before
        not_after = end_time.strftime('%Y%m%dT%H%M%S').encode()
        cert_val.signature_info.validity_period.not_after = not_after
        # prepare signature value
        key_locators = self.annot_model.locate_certs(name)
        for key_locator in key_locators:
            markers = {}
            try:
                signer = self.tpm.get_signer(key_locator[:-2], key_locator)
            except:
                continue
            else:
                cert_val._signer.set_arg(markers, signer)
                value = cert_val.encode(markers=markers)
                shrink_size = cert_val._shrink_len.get_arg(markers)
                type_len = enc.get_tl_num_size(enc.TypeNumber.DATA)
                size_len = enc.get_tl_num_size(len(value) - shrink_size)
                buf = bytearray(type_len + size_len + len(value) - shrink_size)
                enc.write_tl_num(enc.TypeNumber.DATA, buf)
                enc.write_tl_num(len(value) - shrink_size, buf, type_len)
                buf[type_len + size_len:] = memoryview(value)[0:len(value) - shrink_size]
                return buf
        logging.debug(f'No suitable key locators for {enc.Name.to_str(name)} ...')

    async def authenticate_data(self, name: enc.FormalName, sig_ptrs: enc.SignaturePtrs) -> bool:
        return await self.authenticator(name, sig_ptrs)
