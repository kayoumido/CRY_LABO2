from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import strxor
import base64


def generate_tag(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(message)

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

    if len(message) != 32:
        print("ERROR - Message needs to be 265 bits not " + str(len(message)))
        return

    ra = Random.new()
    iv = ra.read(16)

    tag = generate_tag(message, key, iv)
    
    return (base64.b64encode(iv), message, base64.b64encode(tag))#(TODO, message, TODO)

def cbcmac_verify(message, key, iv, tag):
    """
    Verifies the given tag under the improved CBC-MAC


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

    # get the tag based on the given params
    tag_2_compare = generate_tag(message, key, base64.b64decode(iv))

    # check that that given tag and the "new" one are identical
    # if they are, that means the message wasn't altered
    return base64.b64decode(tag) == tag_2_compare


def main():
    m = b"Envoyer 127'000 CHF vers siteABC"
    k = b'Thirty two byte key for AES 256!'

    iv, _, tag = cbcmac(m, k)
    print(iv)
    print(tag)

    print(cbcmac_verify(m, k, iv, tag))

if __name__ == "__main__":
    main()
