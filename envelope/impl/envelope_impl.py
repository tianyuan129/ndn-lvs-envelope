import logging, time, asyncio
from typing import Dict, Optional, Any, Tuple
from ndn.app import NDNApp, Validator
from ndn.security.tpm import Tpm
import ndn.encoding as enc
import ndn.app_support.security_v2 as sv2
import ndn.app_support.light_versec.binary as bny
import ndn.app_support.light_versec.checker as chk

from ..envelope import EnvelopeBase
from ..annot_model import AnnotLvsModel
from ..storage import Box
from .checker.pipelines import make_validator2

class EnvelopeImpl(EnvelopeBase):
    app: NDNApp
    annot_model: AnnotLvsModel
    anchor_name: enc.FormalName
    tpm: Tpm
    validator: Validator
    def __init__(self, app: NDNApp, default_box: Box, tpm: Tpm):
        self.app = app
        self.tpm = tpm
        if not default_box.isIteratable():
            logging.debug(f"Default Box must be iteratable")
            raise Exception
        self.default_box = default_box

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
        await self.default_box.get(enc.Name.from_str("/"), _box_iterater)
    
    def index(self, cert: enc.BinaryStr):
        cert_name = sv2.parse_certificate(cert).name
        self.annot_model.annotate(cert_name)
        logging.info(f"Annnotating {enc.Name.to_str(cert_name)}")

    async def _sign(self, name, encoder, **kwargs):
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
                return encoder(signer)
        logging.debug(f'No matching annotations for {enc.Name.to_str(name)} at local ...')
        
        if 'aggressive_search' not in kwargs or not kwargs['aggressive_search']: return None
        else:
            checker = chk.Checker(self.annot_model.model, self.annot_model.usr_func)
            def _semantic_check(cert):
                cert_name = sv2.parse_certificate(cert).name
                return checker.check(name, cert_name)
            box = kwargs['external_box'] if 'external_box' in kwargs and kwargs['external_box'] is not None\
                                        else self.default_box
            if not box.isIteratable():
                logging.error(f'Current Box is not iteratable')
                return None
            else:
                box_cert = await box.get(enc.Name.from_str("/"), _semantic_check)
                if box_cert is None:
                    logging.debug(f'No suitable key locators for {enc.Name.to_str(name)} in box...')
                    return None
                box_cert_name = sv2.parse_certificate(box_cert).name
                try:
                    signer = self.tpm.get_signer(box_cert_name[:-2], box_cert_name)
                except:
                    pass
                else:
                    return encoder(signer) 

    async def sign_data(self, name: enc.NonStrictName, meta_info: enc.MetaInfo,
                        content: Optional[enc.BinaryStr] = None, 
                        **kwargs) -> Optional[enc.VarBinaryStr]:
        return await self._sign(name, lambda signer: enc.make_data(name, meta_info, content, signer),
                                **kwargs)

    async def sign_interest(self, name: enc.NonStrictName,
                            interest_param: enc.InterestParam, app_param: Optional[enc.BinaryStr] = None,
                            **kwargs) -> Optional[Tuple[enc.Name.FormalName, enc.VarBinaryStr]]:
        
        return await self._sign(name, lambda signer: enc.make_interest(name, interest_param, app_param, signer, need_final_name=True),
                                **kwargs)
                
    async def sign_cert(self, name: enc.NonStrictName, meta_info: enc.MetaInfo, 
                        pub_key: enc.BinaryStr, start_time, end_time,
                        **kwargs) -> Optional[enc.VarBinaryStr]:
        def _cert_finalizer(signer):
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
        return await self._sign(name, lambda signer: _cert_finalizer(signer),
                                **kwargs)

    async def validate(self, name: enc.FormalName, sig_ptrs: enc.SignaturePtrs, externalBox: Box = None) -> bool:
        box = externalBox if externalBox else self.default_box 
        validator = make_validator2(chk.Checker(self.annot_model.model, self.annot_model.usr_func), 
                                    self.app, self.trust_anchor, box)
        return await validator(name, sig_ptrs)
