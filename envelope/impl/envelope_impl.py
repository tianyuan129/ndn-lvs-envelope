import logging, time
from typing import Dict, Optional, Tuple
from ndn.app import NDNApp, Validator
from ndn.security.tpm import Tpm
import ndn.encoding as enc
import ndn.app_support.security_v2 as sv2
import ndn.app_support.light_versec.binary as bny
import ndn.app_support.light_versec.checker as chk

from ..envelope import EnvelopeBase
from ..annot_model import AnnotLvsModel
from ..storage import Box, SearchableBox
from .storage.mem_storage import MemoryBox
from .checker.pipelines import make_validator2

class EnvelopeImpl(EnvelopeBase):
    app: NDNApp
    annot_model: AnnotLvsModel
    anchor_name: enc.FormalName
    tpm: Tpm
    validator: Validator
    def __init__(self, app: NDNApp, tpm: Tpm,
                 local_box: SearchableBox = MemoryBox(),
                 default_external_box: Box | None = None):
        self.app = app
        self.tpm = tpm
        self.default_box = local_box
        self.default_external_box = default_external_box

    async def set(self, trust_anchor: enc.BinaryStr, model: bny.LvsModel, usr_func: Dict = chk.DEFAULT_USER_FNS):
        self.anchor_name = sv2.parse_certificate(trust_anchor).name
        self.trust_anchor = trust_anchor
        self.annot_model = AnnotLvsModel(model, usr_func)
        
        # indexing the default box
        async def _box_iterater(cert):
            cert_name = sv2.parse_certificate(cert).name
            self.annot_model.annotate(cert_name)
            logging.debug(f"Indexing {enc.Name.to_str(cert_name)}")
            return False
        await self.default_box.search(enc.Name.from_str("/"), _box_iterater)
        return self
    
    def index(self, cert: enc.BinaryStr):
        cert_name = sv2.parse_certificate(cert).name
        self.annot_model.annotate(cert_name)
        logging.info(f"Annnotating {enc.Name.to_str(cert_name)}")

    def _sign_local(self, name, encoder):
        before = time.time()
        key_locators = self.annot_model.locate_certs(enc.Name.normalize(name))
        logging.info(f"Annotation Locating Cost {(time.time() - before) * 1000} ms")
        for key_locator in key_locators:
            try:
                before = time.time()
                signer = self.tpm.get_signer(key_locator[:-2], key_locator)
                logging.info(f"(Indexing) Getting signer {(time.time() - before) * 1000} ms")
            except:
                logging.warn(f"No private key of {enc.Name.to_str(key_locator)} in TPM")
                continue
            else:
                return encoder(signer)
        logging.debug(f'No matching annotations for {enc.Name.to_str(name)}...')
        return None

    async def _async_sign(self, name, encoder, **kwargs):
        local = self._sign_local(name, encoder)
        if local is not None: return local
        elif 'aggressive_search' not in kwargs or not kwargs['aggressive_search']: return None
        else:
            checker = chk.Checker(self.annot_model.model, self.annot_model.usr_func)
            async def _semantic_and_tpm_check(cert):
                cert_name = sv2.parse_certificate(cert).name
                if checker.check(name, cert_name):
                    try:
                        signer = self.tpm.get_signer(cert_name[:-2], cert_name)
                    except:
                        logging.warn(f"No private key of {enc.Name.to_str(cert_name)} in TPM")
                        return False
                    else: return True
                else: return False
            # aggressively search local box
            box_cert = await self.default_box.search(enc.Name.from_str("/"), _semantic_and_tpm_check)
            if box_cert is None:
                logging.debug(f'No suitable key locators for {enc.Name.to_str(name)} in local box...')
            else:
                box_cert_name = sv2.parse_certificate(box_cert).name
                signer = self.tpm.get_signer(box_cert_name[:-2], box_cert_name)
                return encoder(signer) 
            # aggressively search external box?
            if 'external_box' in kwargs and kwargs['external_box'] is not None:
                if not isinstance(kwargs['external_box'], SearchableBox):
                    logging.warn(f'External box is not serachable, skipping...')
                else:
                    external_box = kwargs['external_box']
                    box_cert = await external_box.search(enc.Name.from_str("/"), _semantic_and_tpm_check)
                    if box_cert is None:
                        logging.debug(f'No suitable key locators for {enc.Name.to_str(name)} in external box...')
                    else:
                        box_cert_name = sv2.parse_certificate(box_cert).name
                        signer = self.tpm.get_signer(box_cert_name[:-2], box_cert_name)
                        return encoder(signer)

    def sign_data(self, name: enc.NonStrictName, meta_info: enc.MetaInfo,
                  content: Optional[enc.BinaryStr] = None) -> Optional[enc.VarBinaryStr]:
        return self._sign_local(name, lambda signer: enc.make_data(name, meta_info, content, signer))
    
    async def async_sign_data(self, name: enc.NonStrictName, meta_info: enc.MetaInfo,
                              content: Optional[enc.BinaryStr] = None, 
                              **kwargs) -> Optional[enc.VarBinaryStr]:
        return await self._async_sign(name, lambda signer: enc.make_data(name, meta_info, content, signer), **kwargs)

    def sign_interest(self, name: enc.NonStrictName, interest_param: enc.InterestParam, 
                      app_param: Optional[enc.BinaryStr] = None) -> Optional[Tuple[enc.VarBinaryStr, enc.Name.FormalName]]:
        return self._sign_local(name, lambda signer: enc.make_interest(name, interest_param, app_param, signer, need_final_name=True))

    async def async_sign_interest(self, name: enc.NonStrictName, interest_param: enc.InterestParam,
                                  app_param: Optional[enc.BinaryStr] = None, **kwargs) -> Optional[Tuple[enc.VarBinaryStr, enc.Name.FormalName]]:
        return await self._async_sign(name, lambda signer: enc.make_interest(name, interest_param, app_param, signer, need_final_name=True), **kwargs)
    
    def _cert_finalizer(self, name, meta_info, pub_key, start_time, end_time, signer):
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
        markers = {}
        cert_val._signer.set_arg(markers, signer)
        value = cert_val.encode(markers=markers)
        shrink_size = cert_val._shrink_len.get_arg(markers)
        type_len = enc.get_tl_num_size(enc.TypeNumber.DATA)
        size_len = enc.get_tl_num_size(len(value) - shrink_size)
        buf = bytearray(type_len + size_len + len(value) - shrink_size)
        enc.write_tl_num(enc.TypeNumber.DATA, buf)
        enc.write_tl_num(len(value) - shrink_size, buf, type_len)
        buf[type_len + size_len:] = memoryview(value)[0:len(value) - shrink_size]
        # nothing to do with encoding but optimization
        self.index(buf)
        return buf
    
    def sign_cert(self, name: enc.NonStrictName, meta_info: enc.MetaInfo, pub_key: enc.BinaryStr,
                  start_time, end_time) -> Optional[enc.VarBinaryStr]:
        return self._sign_local(name, lambda signer: self._cert_finalizer(enc.Name.normalize(name), meta_info, pub_key,
                                                                          start_time, end_time, signer))

    async def async_sign_cert(self, name: enc.NonStrictName, meta_info: enc.MetaInfo, 
                              pub_key: enc.BinaryStr, start_time, end_time,
                              **kwargs) -> Optional[enc.VarBinaryStr]:
        return await self._async_sign(name, lambda signer: self._cert_finalizer(enc.Name.normalize(name), meta_info, pub_key,
                                                                                start_time, end_time, signer), **kwargs)

    async def validate(self, name: enc.FormalName, sig_ptrs: enc.SignaturePtrs, externalBox: Box = None) -> bool:
        boxes = [self.default_box]
        _externalBox = externalBox if externalBox else self.default_external_box
        if _externalBox:
            boxes.append(_externalBox)
        validator = make_validator2(chk.Checker(self.annot_model.model, self.annot_model.usr_func), 
                                    self.app, self.trust_anchor, boxes)
        return await validator(name, sig_ptrs)
