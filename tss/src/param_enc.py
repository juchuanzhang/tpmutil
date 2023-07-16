from .TpmTypes import TPM_ALG_ID
from .lhmac import NIST
import hashlib
from .Crypt import Crypto
from .Helpers import intToTpm

def KDFa(hashAlg=hashlib.sha1, key=None, label = None, contextU = bytes(), contextV = bytes(), bits = 128):
    obj = NIST.new()
    obj.set_hmac(hashAlg, key)
    outkey = obj.derive_key(label, contextU, contextV, bits)
    return outkey

def authHMAC(alg=TPM_ALG_ID.SHA1, sessionKey=None, authValue=None, pHash=None, nonceNewer=None,
             nonceOlder=None, nonceTPMdec=None, nonceTPMenc=None, sessionAttributes=None):
    key = sessionKey + authValue
    sessionAttributesBytes = intToTpm(sessionAttributes, 1)
    data = pHash + nonceNewer + nonceOlder + nonceTPMdec + nonceTPMenc + sessionAttributesBytes

    digest = Crypto.hmac(alg, key, data)
    return digest

def cpHash(alg=TPM_ALG_ID.SHA1, cmdCode, name1=None, name2=None, name3=None, param):
    cmdCodeBytes = intToTpm(cmdCode, 4)
    data = cmdCodeBytes
    if(name1 is not None):
        data = data + name1
    if (name2 is not None):
        data = data + name2
    if (name3 is not None):
        data = data + name3
    data = data + param
    ret = Crypto.hash(alg, data)
    return ret

def rpHash(alg=TPM_ALG_ID.SHA1, cmdCode, param):
    cmdCodeBytes = intToTpm(cmdCode, 4)
    data = cmdCodeBytes
    data = data + param
    ret = Crypto.hash(alg, data)
    return ret
