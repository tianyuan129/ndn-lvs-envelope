import logging, time
from typing import Dict, Optional, Any, Tuple, List
from ndn.app import NDNApp, Validator
from ndn.security.tpm import Tpm
import ndn.encoding as enc
import ndn.app_support.security_v2 as sv2
import ndn.app_support.light_versec.binary as bny
import ndn.app_support.light_versec.checker as chk

from ..envelope import EnvelopeBase
from ..annot_model import AnnotLvsModel
from ..storage import Storage, Box
from .checker.pipelines import make_validator2

class EnvelopeImpl(EnvelopeBase):
    app: NDNApp
    annot_model: AnnotLvsModel
    anchor_name: enc.FormalName
    tpm: Tpm
    validator: Validator
    def __init__(self, app: NDNApp, tpm: Tpm):
        self.app = app
        self.tpm = tpm

    async def set(self, trust_anchor: enc.BinaryStr, model: bny.LvsModel, usr_func: Dict = chk.DEFAULT_USER_FNS):
        self.anchor_name = sv2.parse_certificate(trust_anchor).name
        self.trust_anchor =  trust_anchor
        self.annot_model = AnnotLvsModel(model, usr_func)
    
    async def index(self, cert: enc.BinaryStr):
        cert_name = sv2.parse_certificate(cert).name
        before = time.time()
        self.annot_model.annotate(cert_name)
        logging.info(f"Annnotation Cost {(time.time() - before) * 1000} ms")
        # await self.cert_storage.put(cert_name, cert)

    async def sign_data(self, box: Box, name: enc.NonStrictName, meta_info: enc.MetaInfo,
                        content: Optional[enc.BinaryStr] = None) -> Optional[enc.VarBinaryStr]:
        before = time.time()
        key_locators = self.annot_model.locate_certs(enc.Name.normalize(name))
        logging.info(f"Annotation Locating Cost {(time.time() - before) * 1000} ms")
        for key_locator in key_locators:
            try:
                before = time.time()
                signer = self.tpm.get_signer(key_locator[:-2], key_locator)
                logging.info(f"(Indexing) Getting signer {(time.time() - before) * 1000} ms")
            except:
                continue
            else:
                before = time.time()
                data = enc.make_data(name, meta_info, content, signer)
                logging.info(f"(Indexing) Crypto and Encoding Cost {(time.time() - before) * 1000} ms")
                return data
        logging.debug(f'No matching annotations for {enc.Name.to_str(name)} ...')
        
        checker = chk.Checker(self.annot_model.model, self.annot_model.usr_func)
        def _semantic_check(cert):
            cert_name = sv2.parse_certificate(cert)
            return checker.check(name, cert_name)
        box_cert = await box.get(enc.Name.from_str("/"), _semantic_check)
        box_cert_name = sv2.parse_certificate(box_cert)
        try:
            signer = self.tpm.get_signer(box_cert_name[:-2], box_cert_name)
        except:
            pass
        else:
            before = time.time()
            data = enc.make_data(name, meta_info, content, signer)
            logging.info(f"(Enumeration) Crypto and Encoding Cost {(time.time() - before) * 1000} ms")
            return data
        

    async def sign_cert(self, box: Box, name: enc.NonStrictName, meta_info: enc.MetaInfo, pub_key: enc.BinaryStr, start_time, end_time) -> Optional[enc.VarBinaryStr]:
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

        checker = chk.Checker(self.annot_model.model, self.annot_model.usr_func)
        def _semantic_check(cert):
            cert_name = sv2.parse_certificate(cert)
            return checker.check(name, cert_name)
        box_cert = await box.get(enc.Name.from_str("/"), _semantic_check)
        box_cert_name = sv2.parse_certificate(box_cert)
        markers = {}
        try:
            signer = self.tpm.get_signer(box_cert_name[:-2], box_cert_name)
        except:
            pass
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

    async def validate(self, box: Box, name: enc.FormalName, sig_ptrs: enc.SignaturePtrs) -> bool:
        validator = make_validator2(chk.Checker(self.annot_model.model, self.annot_model.usr_func), 
                                    self.app, self.trust_anchor, box)
        return await validator(name, sig_ptrs)
