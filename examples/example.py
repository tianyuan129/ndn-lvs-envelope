import os, sys, logging, asyncio
from datetime import datetime, timedelta
from ndn.app import NDNApp
from ndn.security.tpm import TpmFile
from ndn.utils import timestamp
import ndn.encoding as enc
import ndn.app_support.security_v2 as sv2
import ndn.app_support.light_versec.checker as chk
import ndn.app_support.light_versec.compiler as cpl

from tib.impl.tib_impl import TrustInfoBaseImpl
from tib.impl.storage.mem_storage import MemoryStorage
from tib.impl.storage.sqlite3_storage import Sqlite3Storage

logging.basicConfig(format='[{asctime}]{levelname}:{message}',
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

async def main():
    basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
    tpm_path = os.path.join(basedir, 'privKeys')
    db_path = os.path.join(basedir, 'certStorage.db')
    os.makedirs(tpm_path, exist_ok=True)

    Sqlite3Storage.initialize(db_path)
    tib = TrustInfoBaseImpl(NDNApp(), Sqlite3Storage(db_path), TpmFile(tpm_path))
    generated_keys = []
    
    # anchor
    anchor_key_name, anchor_key_pub = tib.add_key("/lvs-test")
    generated_keys.append(anchor_key_name)
    anchor_self_signer = tib.tpm.get_signer(anchor_key_name, None)
    _, anchor_bytes = sv2.self_sign(anchor_key_name, anchor_key_pub, anchor_self_signer)
    chk.DEFAULT_USER_FNS.update(
        {'$eq_any': lambda c, args: any(x == c for x in args)}
    )
    await tib.set(anchor_bytes, cpl.compile_lvs(lvs_text), chk.DEFAULT_USER_FNS)
    await tib.add_certificate(anchor_bytes)

    # admin
    admin_key_name, admin_key_pub = tib.add_key("/lvs-test/admin/alice")
    generated_keys.append(admin_key_name)
    admin_cert_name = admin_key_name + [enc.Component.from_str("anchor"), enc.Component.from_version(timestamp())]
    admin_cert_bytes = tib.sign_cert(admin_cert_name, enc.MetaInfo(content_type=enc.ContentType.KEY, freshness_period=3600000),
                                     admin_key_pub, datetime.utcnow(), datetime.utcnow() + timedelta(days=10))
    await tib.add_certificate(admin_cert_bytes)

    # author
    author_key_name, author_key_pub = tib.add_key("/lvs-test/author/bob")
    generated_keys.append(author_key_name)
    author_cert_name = author_key_name + [enc.Component.from_str("admin"), enc.Component.from_version(timestamp())]
    author_cert_bytes = tib.sign_cert(author_cert_name, enc.MetaInfo(content_type=enc.ContentType.KEY, freshness_period=3600000),
                                      author_key_pub, datetime.utcnow(), datetime.utcnow() + timedelta(days=10))
    await tib.add_certificate(author_cert_bytes)

    post_name = enc.Name.from_str('/lvs-test/article/bob/test/v=1')
    post_bytes = tib.sign_data(post_name, enc.MetaInfo(content_type=enc.ContentType.BLOB, freshness_period=3600000),
                               'Hello World!'.encode())
    # from base64 import b64encode
    # print(b64encode(post_bytes).decode('utf-8'))
    _, _, _, post_sig = enc.parse_data(post_bytes)
    authenticated = await tib.authenticate_data(post_name, post_sig)
    print(authenticated)

    # post
    

    for key in generated_keys:
        tib.tpm.delete_key(key)

    # admin_signer = tib.tpm.get_signer(admin_key_name, None)
    
    # annot_lvs_model = AnnotLvsModel(lvs_model)

    # cert_names = []
    # cert_names += ['/lvs-test/author/b/KEY/123/admin/v=1']
    # cert_names += ['/lvs-test/author/b/KEY/123/admin2/v=1']
    # cert_names += ['/lvs-test/author/x/KEY/123/admin2/v=2']
    # for cert_name in cert_names:
    #     annot_lvs_model.annotate(enc.Name.normalize(cert_name))
    # data_name = enc.Name.normalize('/lvs-test/article/b/post1/v=1')
    # # explore(tib._checker, data_name)
    # print([enc.Name.to_str(cert_name) for cert_name in annot_lvs_model.locate_certs(data_name)])
    # print(annot_lvs_model.encode())

if __name__ == '__main__':
    asyncio.run(main())