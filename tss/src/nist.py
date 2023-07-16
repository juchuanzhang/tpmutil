# -*- coding: utf-8 -*- 
'''
Created on 14/07/2014

@author: Aitor Gomez Goiri
'''
from abc import ABCMeta, abstractmethod

class AbstractNIST(object):
    
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def _get_reseted_hmac(self):
        pass
        
    def set_hmac(self, digestmod, secret, salt=None):
        assert secret != None, "Key derivation key cannot be null."
        self.salt = salt
        self.secret = secret
        self.digestmod = digestmod
            
    # Calculate the size of a key. The key size is given in bits, but we can
    # only allocate them by octets (i.e., bytes), so make sure we round up to
    # the next whole number of octets to have room for all the bits. For
    # example, a key size of 9 bits would require 2 octets to store it.
    # @param ks
    #    The key size, in bits.
    # @return The key size, in octets, large enough to accommodate {@code ks}
    #         bits.
    def _calc_key_size(self, ks):
        assert ks > 0, "Key size must be > 0 bits."
        n = ks / 8
        rem = ks % 8
        return n if rem==0 else n+1
    
    def _to_one_byte(self, inByte):
        assert isinstance( inByte, int ), "This method expected an int as a parameter"
        assert inByte<128, "The maximum value of ctr is 127 (1 byte only)"
        output = bytearray()
        output.append(inByte)
        return output;

    def _to_four_bytes(self, inByte):
        assert isinstance( inByte, int ), "This method expected an int as a parameter"
        assert inByte<2147483648, "The maximum value of ctr is 2147483647 (4 bytes)"
        output = bytes(4)
        for i in range(3,-1,-1):
            output[i] = inByte & 0x000000FF
            inByte = inByte >> 8
        return output
    # def _debug_string_as_bytes(self, array_alpha):
    #     import binascii
    #     print binascii.hexlify(array_alpha)
    
    def derive_key(self, label=None, contextU=bytes(), contextV=bytes(), bits=128):
        assert bits >= 56, "Key has size of %d, which is less than minimum of 56-bits." % bits
        assert (bits % 8) == 0, "Key size (%d) must be a even multiple of 8-bits." % bits
        
        outputSizeBytes = self._calc_key_size(bits) # Safely convert to whole # of bytes.
        derivedKey = [] # bytearray() (better to use this?)
                
        # Repeatedly call of HmacSHA1 hash until we've collected enough bits
        # for the derived key.
        ctr = 1 # Iteration counter for NIST 800-108
        totalCopied = 0
        destPos = 0
        lenn = 0
        tmpKey = None
        
        while True: # ugly translation of do-while
            hmac = self._get_reseted_hmac()
            hmac.update( self._to_four_bytes(ctr) )
            ctr += 1 # note that the maximum value of ctr is 127 (1 byte only)
            zerobyte = bytes(1)
            zerobyte[0] = 0
            if(label is None):
                hmac.update(zerobyte)
            elif(len(label)==0):
                hmac.update(zerobyte)
            elif(label[len(label)]==0):
                hmac.update(label)
            else:
                hmac.update(label)
                hmac.update(zerobyte)

            hmac.update(contextU)
            hmac.update(contextV)
            hmac.update( self._to_four_bytes(bits) )

            tmpKey = hmac.digest() # type: string
            #print self._debug_string_as_bytes(tmpKey)
            # or simply hmac.hexdigest()
            
            if len(tmpKey) >= outputSizeBytes:
                lenn = outputSizeBytes
            else:
                lenn = min(len(tmpKey), outputSizeBytes - totalCopied)
            
            #System.arraycopy(tmpKey, 0, derivedKey, destPos, lenn);
            derivedKey[int(destPos):int(destPos+lenn)] = tmpKey[:int(lenn)]
            totalCopied += len(tmpKey)
            destPos += lenn
            
            if totalCopied >= outputSizeBytes: # ugly translation of do-while
                break
            
            #print ''.join([x.encode("hex") for x in derivedKey]) #[hex(x) for x in derivedKey]
        
        return bytearray( derivedKey )