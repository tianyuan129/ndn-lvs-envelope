import os, sys, logging, asyncio
from datetime import datetime, timedelta
from ndn.app import NDNApp
from ndn.security.tpm import TpmFile
from ndn.utils import timestamp
import ndn.encoding as enc
import ndn.app_support.security_v2 as sv2
import ndn.app_support.light_versec.checker as chk
import ndn.app_support.light_versec.compiler as cpl

from envelope.impl.envelope_impl import EnvelopeImpl
from envelope.impl.storage import MemoryBox, ExpressToNetworkBox

logging.basicConfig(format='[{asctime}][{module}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')

lvs_text = r'''
#KEY: "KEY"/_/_/_
#site: "lvs-test"
#article: #site/"article"/author/post/_version & {_version: $eq_type("v=0")} <= #author
#author: #site/"author"/author/"KEY"/_/_admin/_ & {_admin: $eq_any("admin", "admin2")} <= #admin
#admin: #site/"admin"/admin/#KEY <= #root
#root: #site/#KEY
'''
app = NDNApp()
async def main():
    basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
    tpm_path = os.path.join(basedir, 'privKeys')
    db_path = os.path.join(basedir, 'certStorage.db')
    os.makedirs(tpm_path, exist_ok=True)
    envelope = EnvelopeImpl(app, TpmFile(tpm_path))
    generated_keys = []
    express = ExpressToNetworkBox(app)
    
    # anchor
    anchor_key_name, anchor_key_pub = envelope.tpm.generate_key(enc.Name.from_str("/lvs-test"))
    generated_keys.append(anchor_key_name)
    anchor_self_signer = envelope.tpm.get_signer(anchor_key_name, None)
    anchor_cert_name, anchor_bytes = sv2.self_sign(anchor_key_name, anchor_key_pub, anchor_self_signer)
    chk.DEFAULT_USER_FNS.update(
        {'$eq_any': lambda c, args: any(x == c for x in args)}
    )
    await envelope.set(anchor_bytes, cpl.compile_lvs(lvs_text), chk.DEFAULT_USER_FNS)
    envelope.index(anchor_bytes)
    envelope.default_box.put(anchor_cert_name, anchor_bytes)
    external_box = MemoryBox()

    # admin
    admin_key_name, admin_key_pub = envelope.tpm.generate_key(enc.Name.from_str("/lvs-test/admin/alice"))
    generated_keys.append(admin_key_name)
    admin_cert_name = admin_key_name + [enc.Component.from_str("anchor"), enc.Component.from_version(timestamp())]
    admin_cert_bytes = await envelope.async_sign_cert(admin_cert_name, enc.MetaInfo(content_type=enc.ContentType.KEY, freshness_period=3600000),
                                          admin_key_pub, datetime.utcnow(), datetime.utcnow() + timedelta(days=10),
                                          aggressive_search = True)
    external_box.put(admin_cert_name, admin_cert_bytes)

    # author
    author_key_name, author_key_pub = envelope.tpm.generate_key(enc.Name.from_str("/lvs-test/author/bob"))
    generated_keys.append(author_key_name)
    author_cert_name = author_key_name + [enc.Component.from_str("admin"), enc.Component.from_version(timestamp())]
    author_cert_bytes = envelope.sign_cert(author_cert_name, enc.MetaInfo(content_type=enc.ContentType.KEY, freshness_period=3600000),
                                           author_key_pub, datetime.utcnow(), datetime.utcnow() + timedelta(days=10))
    external_box.put(author_cert_name, author_cert_bytes)

    post_name = enc.Name.from_str('/lvs-test/article/bob/test/v=1')
    post_bytes = envelope.sign_data(post_name, enc.MetaInfo(content_type=enc.ContentType.BLOB, freshness_period=3600000),
                                    'Hello World!'.encode())
    _, _, _, post_sig = enc.parse_data(post_bytes)
    authenticated = await envelope.validate(post_name, post_sig, external_box)
    print(authenticated)

    # post
    for key in generated_keys:
        envelope.tpm.delete_key(key)

if __name__ == '__main__':
    app.run_forever(after_start=main())
