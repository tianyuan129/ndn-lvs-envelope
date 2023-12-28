import logging, time
from typing import Optional, Coroutine, Any, List
from Cryptodome.PublicKey import ECC, RSA
from datetime import datetime

from ndn.app import NDNApp, Validator

from ndn.security.validator.digest_validator import union_checker
from ndn.security.validator.known_key_validator import verify_hmac, verify_ecdsa, verify_rsa
import ndn.encoding as enc
import ndn.app_support.light_versec.checker as chk
import ndn.app_support.security_v2 as sv2

from ...storage import Box
class Pipelines:
    app: NDNApp
    next_level: Validator
    storage: Box
    anchor_key: bytes
    anchor_name: enc.FormalName
    vnames: List[enc.FormalName]

        
    @staticmethod
    def _verify_sig(pub_key_bits, sig_ptrs) -> bool:
        if sig_ptrs.signature_info.signature_type == enc.SignatureType.HMAC_WITH_SHA256:
            verify_hmac(pub_key_bits, sig_ptrs)
        elif sig_ptrs.signature_info.signature_type == enc.SignatureType.SHA256_WITH_RSA:
            pub_key = RSA.import_key(bytes(pub_key_bits))
            return verify_rsa(pub_key, sig_ptrs)
        elif sig_ptrs.signature_info.signature_type == enc.SignatureType.SHA256_WITH_ECDSA:
            pub_key = ECC.import_key(bytes(pub_key_bits))
            return verify_ecdsa(pub_key, sig_ptrs)
        else:
            return False

    def __init__(self, app: NDNApp, trust_anchor: enc.BinaryStr, storage: Box):
        self.app = app
        self.next_level = self
        self.storage = storage
        cert_name, _, key_bits, sig_ptrs = enc.parse_data(trust_anchor)
        self.anchor_name = [bytes(c) for c in cert_name]  # Copy the name in case
        self.anchor_key = bytes(key_bits)
        self.vnames = [cert_name]
        if not self._verify_sig(self.anchor_key, sig_ptrs):
            raise ValueError('Trust anchor is not properly self-signed')

    async def _validator_wrapper(self, cert):
        name, _, _, sig_ptrs = enc.parse_data(cert)
        return await self.next_level(name, sig_ptrs)

    async def validate(self, name: enc.FormalName, sig_ptrs: enc.SignaturePtrs) -> bool:
        if (not sig_ptrs.signature_info or not sig_ptrs.signature_info.key_locator
                or not sig_ptrs.signature_info.key_locator.name):
            return False
        # Obtain public key
        cert_name = sig_ptrs.signature_info.key_locator.name
        logging.debug(f'Verifying {enc.Name.to_str(name)} <- {enc.Name.to_str(cert_name)} ...')
        key_bits = None
        if cert_name == self.anchor_name:
            logging.debug('Use trust anchor.')
            key_bits = self.anchor_key
        else:
            # check vnames
            if cert_name in self.vnames:
                logging.info(f"Getting {enc.Name.to_str(cert_name)} Cost {(time.time() - before) * 1000} ms")

            before = time.time()
            if cert_name in self.vnames:
                logging.debug(f'Cached result, bypassing pipeline...')
                packet = await self.storage.get(cert_name, filter = None)
            else:
                packet = await self.storage.get(cert_name, self._validator_wrapper)
            logging.info(f"Getting {enc.Name.to_str(cert_name)} Cost {(time.time() - before) * 1000} ms")
            if packet:
                try:
                    cert = sv2.parse_certificate(packet)
                except:
                    logging.debug(f'Cannot parse the received certificate, fails ...')
                    return False
                else:
                    self.vnames.append(cert.name)
                    key_bits = cert.content
                    not_before_str = bytes(cert.signature_info.validity_period.not_before).decode('utf-8')
                    not_before_time = datetime.strptime(not_before_str, '%Y%m%dT%H%M%S')
                    not_after_str = bytes(cert.signature_info.validity_period.not_after).decode('utf-8')
                    not_after_time = datetime.strptime(not_after_str, '%Y%m%dT%H%M%S')
                    now_time = datetime.utcnow()
                    if not_before_time > now_time or not_after_time < now_time:
                        logging.debug(f'Certificate validity period not started or already ended, fails ...')
                        return False
        # Validate signature
        if not key_bits:
            return False
        before = time.time()
        result = self._verify_sig(key_bits, sig_ptrs)
        logging.info(f"Pure Crypto Cost {(time.time() - before) * 1000} ms")
        return result
        

    def __call__(self, name: enc.FormalName, sig_ptrs: enc.SignaturePtrs) -> Coroutine[Any, None, bool]:
        return self.validate(name, sig_ptrs)

def make_validator2(checker: chk.Checker, app: NDNApp, trust_anchor: enc.BinaryStr,
                    storage: Box) -> Validator:
    async def validate_name(name: enc.FormalName, sig_ptrs: enc.SignaturePtrs) -> bool:
        if (not sig_ptrs.signature_info or not sig_ptrs.signature_info.key_locator
                or not sig_ptrs.signature_info.key_locator.name):
            return False
        cert_name = sig_ptrs.signature_info.key_locator.name
        logging.debug(f'LVS Checking {enc.Name.to_str(name)} <- {enc.Name.to_str(cert_name)} ...')
        before = time.time()
        result = checker.check(name, cert_name)
        logging.info(f"Semantic Checking Cost {(time.time() - before) * 1000} ms")
        return result

    def sanity_check():
        root_of_trust = checker.root_of_trust()
        if not checker.validate_user_fns():
            raise ValueError('Missing user functions for LVS validator')
        cert_name, _, _, _ = enc.parse_data(trust_anchor)
        ta_matches = sum((m[0] for m in checker.match(cert_name)), start=[])
        if not ta_matches or not root_of_trust.issubset(ta_matches):
            raise ValueError('Trust anchor does not match all roots of trust of LVS model')

    sanity_check()
    cas_checker = Pipelines(app, trust_anchor, storage)
    ret = union_checker(validate_name, cas_checker)
    cas_checker.next_level = ret
    return ret