from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import strxor
import base64


def compute_tag(message, key, iv):
    """
    Computes the tag of the improved CBC-MAC


    @type message: bytes
    @param message: message to authenticate.

    @type key: bytes
    @param key: An AES-256 key

    @type iv: bytes
    @param iv: the IV in base64 under which tto compute the tag 

    @rtype: bytes
    @returns: the tag (i.e. the last block of the ciphertext)
    """

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(message)[AES.block_size:]


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

    # generate the IV the use
    ra = Random.new()
    iv = ra.read(AES.block_size)

    # compute the tag
    tag = compute_tag(message, key, iv)
    
    return (base64.b64encode(iv), message, base64.b64encode(tag))


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
    tag_2_compare = compute_tag(message, key, base64.b64decode(iv))

    # check that that given tag and the "new" one are identical
    # if they are, that means the message wasn't altered
    return base64.b64decode(tag) == tag_2_compare


def cbcmac_break(og_message, forgery, og_iv):
    """
    Generates a new IV, which will allow the forgery and the original text to have the same tag

    @note: Only the first block of the original message can be forged.
    Why? Simply because we, the attacker, have control over the IV and the first bloc of the message.

    For the forgery to have the same CBC-MAC as the original message, we need to create a new IV so that 
    og_message[0] XOR og_iv = forgery[0] XOR new_iv

    @type   og_message: bytes
    @param  og_message: the original message to forge

    @type   forgery: bytes
    @param  forgery: the forgery that will replace the FIRST BLOCK of the original message

    @type   og_iv: bytes
    @param  og_iv: the IV in base64 under which the tag was computed. 

    @rtype: bytes
    @returns: the forged IV
    """
    # get the frist block of the original message
    fblock = og_message[:AES.block_size]
    # decode the original IV
    iv = base64.b64decode(og_iv)

    # calculate the value used to calculate the first block that will be ciphered
    # by AES-256
    block_before_cipher = strxor.strxor(fblock, iv)

    # calculate (and return) the IV that will allow the forged text to have an
    # identical tag to the original message
    return base64.b64encode(strxor.strxor(forgery, block_before_cipher))


def main():
    print("Welcome to the \"improved\" CBC-MAC tool")
    print("--------------------------------------")
    print()

    message = b"YES! I will go out we you George"
    key     = b"Thirty two byte key for AES 256!"
    forgery = b"NO!! I wont go out we you George"

    print("Tagging message to send")
    print("-----------------------")
    print("Message to tag: {}".format(message))
    print("AES-256 key used: {}".format(key))

    print()
    print("Computing tag and IV...")
    print()

    iv, _, tag = cbcmac(message, key)
    print("Base64 tag: {}".format(tag))
    print("Base64 IV: {}".format(iv))

    print()
    print("(Fake)Sending message...")
    print()

    print("Verifying CBC-MAC... Tag ", end ="")
    print("valid" if cbcmac_verify(message, key, iv, tag) else "invalid")

    print()

    print("Forgery time")
    print("------------")
    print("Forged message: {}".format(forgery))

    print()
    print("(Fake)Sending message with the original IV...")
    print()

    print("Verifying CBC-MAC... Tag ", end ="")
    print("valid" if cbcmac_verify(forgery, key, iv, tag) else "invalid")

    print()

    print("Breaking improved CBC-MAC")
    print("-------------------------")
    forged_iv = cbcmac_break(message, forgery[:AES.block_size], iv)
    print("Base64 forged IV: {}".format(forged_iv))
    print()
    print("(Fake)Sending message with the forged IV...")
    print()
    print("Verifying CBC-MAC... Tag ", end ="")
    print("valid" if cbcmac_verify(forgery, key, forged_iv, tag) else "invalid")

    print("\n\n")

    print("Forging lab parameters")
    print("----------------------")
    message = b"Envoyer 127'000 CHF vers siteABC"
    iv      = b"3yWzjgcGT0JY5qgP62gFCA=="
    tag     = b"bqhdQnGwCCTcyWny0UOqRQ=="
    forgery = b"Envoyer 927'000 CHF vers siteABC"

    print("Parameters:")
    print("Original message: {}".format(message))
    print("Original base64 IV: {}".format(iv))
    print("Base64 tag: {}".format(tag))

    print()
    print("Forging message")
    print("---")
    print("Forged message: {}".format(forgery))
    forged_iv= cbcmac_break(message, forgery[:AES.block_size], iv)
    print("Base64 forged IV: {}".format(forged_iv))

    print()
    print("Comparing 1st block before AES-256 ciphering")
    print("---")
    print("Original message: {}".format(strxor.strxor(message[:AES.block_size], base64.b64decode(iv))))
    print("Forged message  : {}".format(strxor.strxor(forgery[:AES.block_size], base64.b64decode(forged_iv))))



if __name__ == "__main__":
    main()
