from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import strxor
import base64

def cbcmac(message, key):
    """
    Computes the improved CBC-MAC of the message under the given key.
    @type message: bytes
    @param message: message to authenticate. This message *has* to be a 256-bit message to avoid extension attacks
    @type key: bytes
    @param key: An AES-256 key (see Crypto.Cipher.AES)
    @rtype: (bytes, bytes, bytes)
    @returns: a tuple consisting of the IV in base64, the message, and the tag in base64
    """
    return #(TODO, message, TODO)

def cbcmac_verify(message, key, iv, tag):
    """
    Verifies the given tag under the  improved CBC-MAC
    @type message: bytes
    @param message: the authenticated message.
    @type key: bytes
    @param key: An AES-256 key (see Crypto.Cipher.AES)
    @type iv: bytes
    @param iv: the IV in base64 under which the tag was computed. 
    @type tag: bytes
    @param tag: the tag in base64
    @rtype: boolean
    @returns: true if the tag is valid. False otherwise. 
    """
    return #TODO

