from .TpmTypes import TPM_ALG_ID
from .lhmac import NIST
import hashlib
from .Crypt import Crypto

def KDFa(hashAlg=hashlib.sha1, key=None, label = None, contextU = bytes(), contextV = bytes(), bits = 128):
    obj = NIST.new()
    obj.set_hmac(hashAlg, key)
    outkey = obj.derive_key(label, contextU, contextV, bits)
    return outkey

def authHMAC(alg=TPM_ALG_ID.SHA1, sessionKey=None, authValue=None, pHash=None, nonceNewer=None,
             nonceOlder=None, nonceTPMdec=None, nonceTPMenc=None, sessionAttributes=None):
    key = bytes.fromhex(sessionKey.hex()+authValue.hex())
    data = bytes.fromhex(pHash.hex()+nonceNewer.hex()+nonceOlder.hex()+nonceTPMdec.hex()+
                         nonceTPMenc.hex()+sessionAttributes.hex())
    digest = Crypto.hmac(alg, key, data)
    return digest

def pHash()
