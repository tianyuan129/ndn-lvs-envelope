
import ndn.encoding as enc
import ndn.app_support.light_versec.binary as bny

class TypeNumber:
    LVS_MODEL = 0xa1
    IDX_ANNOTATIONS = 0xa2
    ANNOTATION = 0xa3
    MODEL_CONTEXT = 0xa4

class ModelContext(enc.TlvModel):
    pattern = enc.UintField(bny.TypeNumber.PATTERN_TAG)
    value = enc.BytesField(bny.TypeNumber.COMPONENT_VALUE)

class Annotation(enc.TlvModel):
    cert_name = enc.NameField()
    model_index = enc.RepeatedField(enc.UintField(bny.TypeNumber.NODE_ID))
    # the tlv encoding of context dictionary
    model_context = enc.RepeatedField(enc.ModelField(TypeNumber.MODEL_CONTEXT, ModelContext))

class IdxAnnotations(enc.TlvModel):
    # indexed by node id in LvsModel
    idx = enc.UintField(bny.TypeNumber.NODE_ID)
    annotations = enc.RepeatedField(enc.ModelField(TypeNumber.ANNOTATION, Annotation))