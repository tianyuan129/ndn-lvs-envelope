from typing import Dict
import ndn.encoding as enc
import ndn.app_support.light_versec.binary as bny
import ndn.app_support.light_versec.checker as chk

from .binary import TypeNumber, Annotation, IdxAnnotations, ModelContext

class AnnotLvsModel(enc.TlvModel):
    model = enc.ModelField(TypeNumber.LVS_MODEL, bny.LvsModel)
    idx_annotations = enc.RepeatedField(enc.ModelField(TypeNumber.IDX_ANNOTATIONS, IdxAnnotations))
    usr_func: Dict
    def __init__(self, model: bny.LvsModel, usr_func: Dict = chk.DEFAULT_USER_FNS):
        self.model = model
        self.usr_func = usr_func
    def _get_annotation(self, name):
        model_index = []
        model_context = {}
        checker = chk.Checker(self.model, self.usr_func)
        for node_id, context in checker._match(name, {}):
            model_index.append(node_id)
            model_context.update(context)
        return model_index, model_context

    def annotate(self, cert_name: enc.FormalName):
        annot_cert = Annotation()
        model_idx, model_ctx = self._get_annotation(cert_name)
        annot_cert.cert_name = cert_name
        annot_cert.model_index = model_idx
        annot_cert.model_context = []
        for pattern in model_ctx:
            m_ctx = ModelContext()
            m_ctx.pattern = pattern
            m_ctx.value = model_ctx[pattern]
            annot_cert.model_context.append(m_ctx)
        
        for m_idx in model_idx:
            if self.idx_annotations is None:
                # initialize
                idx_annot_certs = IdxAnnotations()
                idx_annot_certs.idx = m_idx
                idx_annot_certs.annotations = [annot_cert]
                self.idx_annotations = [idx_annot_certs]
            else:
                all_idxs = [entry.idx for entry in self.idx_annotations]
                try:
                    pos = all_idxs.index(m_idx)
                except ValueError:
                    # such entry does not exist
                    idx_annot_certs = IdxAnnotations()
                    idx_annot_certs.idx = m_idx
                    idx_annot_certs.annotations = [annot_cert]
                    self.idx_annotations.append(idx_annot_certs)
                else:
                    self.idx_annotations[pos].annotations.append(annot_cert)

    def locate_certs(self, data_name: enc.FormalName):
        signer_certs = []
        checker = chk.Checker(self.model, self.usr_func)
        for data_node_id, context in checker._match(data_name, {}):
            data_node = self.model.nodes[data_node_id]
            for signer_node in data_node.sign_cons:
                try:
                    idx_pos = [entry.idx for entry in self.idx_annotations].index(signer_node)
                except ValueError:
                    # not signable, skip
                    continue
                else:
                    for annot in self.idx_annotations[idx_pos].annotations:
                        annot_ctx = annot.model_context
                        # reverse to a context dictionary
                        annot_ctx_dict = {}
                        for ctx in annot_ctx:
                            annot_ctx_dict.update({ctx.pattern: ctx.value})
                        # checking context intersection
                        inter_ctx = context.keys() & annot_ctx_dict.keys()
                        # matching patterns
                        pattern_mismatch = False
                        for pattern in inter_ctx:
                            if context[pattern] != annot_ctx_dict[pattern]:
                                pattern_mismatch = True
                                break
                        if not pattern_mismatch:
                            signer_certs += [annot.cert_name]
        return signer_certs