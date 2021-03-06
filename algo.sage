from Crypto.Cipher import AES
import base64


def bytesToGFVector(b):
    """
    Converts a 128-bit python byte-string into a vector of 128 values in GF(2)
    PAS BESOIN DE COMPRENDRE COMMENT FONCTIONNE CETTE FONCTION

    @type b: bytes
    @param b: A 128-bit byte-string
    @rtype: Sage vector over GF(2) 
    @returns: The corresponding vector of size 128
    """
    l =  [int(c) for c in "".join([format(i,"08b") for i in b])]
    V = VectorSpace(GF(2), 128)
    return V(l)


def GFVectorToBytes(vector):
    """
    Converts a vector of 128 values in GF(2) into a 128-bit python byte-string
    PAS BESOIN DE COMPRENDRE COMMENT FONTIONNE CETTE FONCTION

    @type vector: Sage Vector over GF(2)
    @param vector: A vector of size 128 in GF(2).
    @rtype: bytes
    @returns: The corresponding bytes
    """
    return bytes([int(x,2) for x in list(map(str,[''.join(map(str,vector))[i:i+8] for i in range(0, len(vector), 8)]))])


def fillKey1(key):
    """
    Takes a 128bit key and returns an invertible 128x128 matrix which is upper-triangular. 
    This matrix is used as a first part of the encryption key

    @type key: bytes
    @param key: A 128-bit key
    @rtype 128x128 Matrix over GF(2)
    @returns: an inverible matrix over GF(2) which is upper-triangular
    """
    keyVector = bytesToGFVector(key)
    G  = MatrixSpace(GF(2), 128,128)
    res = copy(G.one()); #Identity matrix. Need to copy to be able to modify
    for i in range(128): #line
        for j in range(i+1,128): #column
            res[i,j] = keyVector[(i+j)%128]
    return res


def keyGen(key):
    """
    Generates the two keys used in the cipher given an 128-bit key

    @type key: bytes
    @param key: A 128-bit key
    @rtype: (128x128 Matrix over GF(2), Vector over GF(2) of size 2)
    @returns: a tuple consisting of one invertible matrix and one vector
    """
    cipher = AES.new(key, AES.MODE_ECB)
    key1 = fillKey1(cipher.encrypt(b"\x00"*16))
    key2 = cipher.encrypt(b"\xff"*16)
    return (key1, bytesToGFVector(key2))


def encrypt(message, key):
    """
    Encrypts a 128-bit plaintext into a 128-bit ciphertext using a 128-bit key

    @type message: bytes
    @param message: The 128-bit message to encrypt
    @type key: bytes
    @param key: The 128-bit key to use for encryption
    @rtype: bytes
    @returns: a 128-bit ciphertext corresponding to key1*message+key2
    """
    if len(message) != len(key) != 16:
        print("message and key have to be 128-bit long")
        return
    (key1, key2) = keyGen(key)
    return GFVectorToBytes((key1*bytesToGFVector(message) + key2))


def decrypt(ciphertext, key):
    """
    Decrypts a 128-bit ciphertext into a 128-bit plaintext using a 128-bit key

    @type ciphertext: bytes
    @param ciphertext: The 128-bit message to decrypt
    @type key: bytes
    @param key: The 128-bit key to use for decryption
    @rtype: bytes
    @returns: a 128-bit plaintext corresponding to key1^(-1)*(ciphertext - key2)
    """
    # generate the keys used by the encryption
    (key1, key2) = keyGen(key)

    return GFVectorToBytes((key1^(-1)*(bytesToGFVector(ciphertext) - key2)))


def affine_cipher_attack(known_pairs, extra_pair, to_break):
    """
    
    @type known_pairs: [(bytes, bytes)]
    @param known_pairs: A list of 128 known pairs (plaintext -> ciphertext)

    @type extra_pair: (bytes, bytes)
    @param extra_pair: Extra known pair so we can perform the attack

    @type to_break: bytes
    @param to_break: a 128-bit ciphertext

    @rtype: bytes
    @returns: The plaintext corresponding to <to_break>
    """

    M = MatrixSpace(GF(2), 128, 128)
    # Create 2 matrices. One with the ciphertexts as the cols and the other with the plaintexts as the cols
    CT = M.matrix([bytesToGFVector(ct) - bytesToGFVector(extra_pair[1]) for _, ct in known_pairs]).T
    PT = M.matrix([bytesToGFVector(pt) for pt, _ in known_pairs]).T

    K = CT*PT^(-1)
    k = bytesToGFVector(extra_pair[1]) - K*bytesToGFVector(extra_pair[0])

    # Do some scary math to find the plaintext
    return GFVectorToBytes((K^(-1)*(bytesToGFVector(to_break) - k)))


def main():
    print("Welcome to the <insert algorithm name> tool")
    print("--------------------------------------")
    print()

    message = b"CRY is awesome!!"
    key     = b"YELLOW SUBMARINE"

    print("Testing decryption")
    print("------------------")

    print("Message to encrypt: {}".format(message))
    print("AES-128 key used: {}".format(key))

    print("Encrypting...")
    ct = encrypt(message, key)
    print("Encrypted message: {}".format(ct))

    print("Decrypting...")
    og_message = decrypt(ct, key)
    print("Decrypted message: {}".format(og_message))

    print("\n")

    print("A new challenger approaches")
    print("---------------------------")

    pairs = [(b'gAAAAAAAAAAAAAAAAAAAAA==', b'cmdM2WS60RnYAas952nVwA=='), (b'wAAAAAAAAAAAAAAAAAAAAA==', b'MmdM2WS60RnYAas952nVwA=='), (b'4AAAAAAAAAAAAAAAAAAAAA==', b'0mdM2WS60RnYAas952nVwA=='), (b'8AAAAAAAAAAAAAAAAAAAAA==', b'AmdM2WS60RnYAas952nVwA=='), (b'+AAAAAAAAAAAAAAAAAAAAA==', b'umdM2WS60RnYAas952nVwA=='), (b'/AAAAAAAAAAAAAAAAAAAAA==', b'zmdM2WS60RnYAas952nVwA=='), (b'/gAAAAAAAAAAAAAAAAAAAA==', b'KGdM2WS60RnYAas952nVwA=='), (b'/wAAAAAAAAAAAAAAAAAAAA==', b'5WdM2WS60RnYAas952nVwA=='), (b'/4AAAAAAAAAAAAAAAAAAAA==', b'fudM2WS60RnYAas952nVwA=='), (b'/8AAAAAAAAAAAAAAAAAAAA==', b'SadM2WS60RnYAas952nVwA=='), (b'/+AAAAAAAAAAAAAAAAAAAA==', b'J0dM2WS60RnYAas952nVwA=='), (b'//AAAAAAAAAAAAAAAAAAAA==', b'+tdM2WS60RnYAas952nVwA=='), (b'//gAAAAAAAAAAAAAAAAAAA==', b'Qc9M2WS60RnYAas952nVwA=='), (b'//wAAAAAAAAAAAAAAAAAAA==', b'N/tM2WS60RnYAas952nVwA=='), (b'//4AAAAAAAAAAAAAAAAAAA==', b'251M2WS60RnYAas952nVwA=='), (b'//8AAAAAAAAAAAAAAAAAAA==', b'A1JM2WS60RnYAas952nVwA=='), (b'//+AAAAAAAAAAAAAAAAAAA==', b'ss7M2WS60RnYAas952nVwA=='), (b'///AAAAAAAAAAAAAAAAAAA==', b'0faM2WS60RnYAas952nVwA=='), (b'///gAAAAAAAAAAAAAAAAAA==', b'F4Ys2WS60RnYAas952nVwA=='), (b'///wAAAAAAAAAAAAAAAAAA==', b'm2dc2WS60RnYAas952nVwA=='), (b'///4AAAAAAAAAAAAAAAAAA==', b'gqWE2WS60RnYAas952nVwA=='), (b'///8AAAAAAAAAAAAAAAAAA==', b'sSAg2WS60RnYAas952nVwA=='), (b'///+AAAAAAAAAAAAAAAAAA==', b'1iti2WS60RnYAas952nVwA=='), (b'////AAAAAAAAAAAAAAAAAA==', b'GD3h2WS60RnYAas952nVwA=='), (b'////gAAAAAAAAAAAAAAAAA==', b'hBDlWWS60RnYAas952nVwA=='), (b'////wAAAAAAAAAAAAAAAAA==', b'vErtGWS60RnYAas952nVwA=='), (b'////4AAAAAAAAAAAAAAAAA==', b'zP79eWS60RnYAas952nVwA=='), (b'////8AAAAAAAAAAAAAAAAA==', b'LZbdiWS60RnYAas952nVwA=='), (b'////+AAAAAAAAAAAAAAAAA==', b'70acUWS60RnYAas952nVwA=='), (b'/////AAAAAAAAAAAAAAAAA==', b'auYf9WS60RnYAas952nVwA=='), (b'/////gAAAAAAAAAAAAAAAA==', b'YacYt2S60RnYAas952nVwA=='), (b'/////wAAAAAAAAAAAAAAAA==', b'dyUWNGS60RnYAas952nVwA=='), (b'/////4AAAAAAAAAAAAAAAA==', b'WiELMOS60RnYAas952nVwA=='), (b'/////8AAAAAAAAAAAAAAAA==', b'ACkxOSS60RnYAas952nVwA=='), (b'/////+AAAAAAAAAAAAAAAA==', b'tDlFKgS60RnYAas952nVwA=='), (b'//////AAAAAAAAAAAAAAAA==', b'3BmtDHS60RnYAas952nVwA=='), (b'//////gAAAAAAAAAAAAAAA==', b'DFh9QIy60RnYAas952nVwA=='), (b'//////wAAAAAAAAAAAAAAA==', b'rNvd2Xi60RnYAas952nVwA=='), (b'//////4AAAAAAAAAAAAAAA==', b'7dyc6pa60RnYAas952nVwA=='), (b'//////8AAAAAAAAAAAAAAA==', b'b9IejUu60RnYAas952nVwA=='), (b'//////+AAAAAAAAAAAAAAA==', b'a88aQvM60RnYAas952nVwA=='), (b'///////AAAAAAAAAAAAAAA==', b'Y/UT3YJ60RnYAas952nVwA=='), (b'///////gAAAAAAAAAAAAAA==', b'c4EA42Da0RnYAas952nVwA=='), (b'///////wAAAAAAAAAAAAAA==', b'U2kmnqXK0RnYAas952nVwA=='), (b'///////4AAAAAAAAAAAAAA==', b'ErlqZS/C0RnYAas952nVwA=='), (b'///////8AAAAAAAAAAAAAA==', b'kRnzkjvO0RnYAas952nVwA=='), (b'///////+AAAAAAAAAAAAAA==', b'lljAfBPU0RnYAas952nVwA=='), (b'////////AAAAAAAAAAAAAA==', b'mNqnoEPj0RnYAas952nVwA=='), (b'////////gAAAAAAAAAAAAA==', b'hd5oGOOPURnYAas952nVwA=='), (b'////////wAAAAAAAAAAAAA==', b'v9f3aaNXkRnYAas952nVwA=='), (b'////////4AAAAAAAAAAAAA==', b'y8TJiyLm8RnYAas952nVwA=='), (b'////////8AAAAAAAAAAAAA==', b'I+K0TiGEARnYAas952nVwA=='), (b'////////+AAAAAAAAAAAAA==', b'865PxCdB+RnYAas952nVwA=='), (b'/////////AAAAAAAAAAAAA==', b'Uze40CrKHRnYAas952nVwA=='), (b'/////////gAAAAAAAAAAAA==', b'EgRW+DHd1xnYAas952nVwA=='), (b'/////////wAAAAAAAAAAAA==', b'kGOKqAfyRBnYAas952nVwA=='), (b'/////////4AAAAAAAAAAAA==', b'lKwyCGutY5nYAas952nVwA=='), (b'/////////8AAAAAAAAAAAA==', b'nTNDSLMTLdnYAas952nVwA=='), (b'/////////+AAAAAAAAAAAA==', b'jg2hyQJvsXnYAas952nVwA=='), (b'//////////AAAAAAAAAAAA==', b'qHBkymCWiEnYAas952nVwA=='), (b'//////////gAAAAAAAAAAA==', b'5IvuzKVk+hHYAas952nVwA=='), (b'//////////wAAAAAAAAAAA==', b'fXz6wS6AHr3YAas952nVwA=='), (b'//////////4AAAAAAAAAAA==', b'TpLS2jlJ1+vYAas952nVwA=='), (b'//////////8AAAAAAAAAAA==', b'KU6C7BbaRULYAas952nVwA=='), (b'//////////+AAAAAAAAAAA==', b'5vYigEn9YBFYAas952nVwA=='), (b'///////////AAAAAAAAAAA==', b'eYdiWPezKrcYAas952nVwA=='), (b'///////////gAAAAAAAAAA==', b'R2Xj6Ysvv/v4Aas952nVwA=='), (b'///////////wAAAAAAAAAA==', b'OqDgi3IWlWIoAas952nVwA=='), (b'///////////4AAAAAAAAAA==', b'wSrmToBkwFGQAas952nVwA=='), (b'///////////8AAAAAAAAAA==', b'Nj7rxWSAajbkAas952nVwA=='), (b'///////////+AAAAAAAAAA==', b'2Bbw0q1JPvgCAas952nVwA=='), (b'////////////AAAAAAAAAA==', b'BEbG/T7bl2XPAas952nVwA=='), (b'////////////gAAAAAAAAA==', b'vOaqohn+xF5Ugas952nVwA=='), (b'////////////wAAAAAAAAA==', b'zaZyHFe0Yiljwas952nVwA=='), (b'////////////4AAAAAAAAA==', b'LyfDYMshLscNIas952nVwA=='), (b'////////////8AAAAAAAAA==', b'6iShmfILtxvQsas952nVwA=='), (b'////////////+AAAAAAAAA==', b'YCJka4BehKJrqas952nVwA=='), (b'/////////////AAAAAAAAA==', b'dC/vj2T049Ednas952nVwA=='), (b'/////////////gAAAAAAAA==', b'XDT4Rq2gLTfx+6s952nVwA=='), (b'/////////////wAAAAAAAA==', b'DALX1T8JsPopNKs952nVwA=='), (b'/////////////4AAAAAAAA==', b'rG6I8hpai2GYqCs952nVwA=='), (b'/////////////8AAAAAAAA==', b'7LY2vFD8/Fb7kGs952nVwA=='), (b'/////////////+AAAAAAAA==', b'bQdKIMWwEjg94Ms952nVwA=='), (b'//////////////AAAAAAAA==', b'bmWzGe8pzuWxAbs952nVwA=='), (b'//////////////gAAAAAAA==', b'aKBBa7oad16ow2M952nVwA=='), (b'//////////////wAAAAAAA==', b'ZSuljxB9BCibRsc952nVwA=='), (b'//////////////4AAAAAAA==', b'fjxsRkSz4sT8TYU952nVwA=='), (b'//////////////8AAAAAAA==', b'SBP/1O0uLxwyWwY952nVwA=='), (b'//////////////+AAAAAAA==', b'JEzY8b4VtK2udgK952nVwA=='), (b'///////////////AAAAAAA==', b'/PKWuxhig86WLAr952nVwA=='), (b'///////////////gAAAAAA==', b'TY4KLlSM7QjmmBqd52nVwA=='), (b'///////////////wAAAAAA==', b'L3czBM1QMIQH8Dpt52nVwA=='), (b'///////////////4AAAAAA==', b'6oVBUf7pi53FIHu152nVwA=='), (b'///////////////8AAAAAA==', b'YWGl+5ma/a5AgPgR52nVwA=='), (b'///////////////+AAAAAA==', b'dqhsr1d8EclLwf9T52nVwA=='), (b'////////////////AAAAAA==', b'WTv+BsqxyQddQ/HQ52nVwA=='), (b'////////////////gAAAAA==', b'BhzbVfEqeJtwR+zUZ2nVwA=='), (b'////////////////wAAAAA==', b'uFKR84YdG6MqT9bdp2nVwA=='), (b'////////////////4AAAAA==', b'xM4Ev2hz3dOeX6LOh2nVwA=='), (b'////////////////8AAAAA==', b'PfcuJrSuUTL2f0ro92nVwA=='), (b'////////////////+AAAAA==', b'z4V7FQ0VSPAmPpqkD2nVwA=='), (b'/////////////////AAAAA==', b'K2HRcn5je3WGvTo9+2nVwA=='), (b'/////////////////gAAAA==', b'4qiFvJiPHH7HunsOFWnVwA=='), (b'/////////////////wAAAA==', b'cTosIVVX0mhFtPlpyGnVwA=='), (b'/////////////////4AAAA==', b'Vh9/Gs7mTkVBqf2mcOnVwA=='), (b'/////////////////8AAAA==', b'GFXZbfmFdh9Jk/Q5AanVwA=='), (b'/////////////////+AAAA==', b'hMCVg5dDBqtZ5+cH4wnVwA=='), (b'//////////////////AAAA==', b'veoMX0rP58N5D8F6JhnVwA=='), (b'//////////////////gAAA==', b'z78/5vHWJRM4342BrBHVwA=='), (b'//////////////////wAAA==', b'KxVYlYfloLO7fxR2uB3VwA=='), (b'//////////////////4AAA==', b'4kGWc2uCq/K8PieYkAfVwA=='), (b'//////////////////8AAA==', b'cOgLvrNMvXCyvEBEwDDVwA=='), (b'//////////////////+AAA==', b'VbswJQLQkHSvuI/8YFxVwA=='), (b'///////////////////AAA==', b'Hx1HEmHoynyVsRCNIISVwA=='), (b'///////////////////gAA==', b'ilGpfKeYfmzhoi5voTX1wA=='), (b'///////////////////wAA==', b'oMh1oSt5FkwJhFOqolcFwA=='), (b'///////////////////4AA==', b'9fvMGjK7xg3ZyKggpJL9wA=='), (b'///////////////////8AA==', b'X5y/bAE+Zo55UV80qRkZwA=='), (b'///////////////////+AA==', b'C1JZgGY1J4k4YrEcsg7TwA=='), (b'////////////////////AA==', b'os+UWKgjpYe6BW1MhCFAwA=='), (b'////////////////////gA==', b'8fQP6TQOoZq+ytXs6H5nQA=='), (b'////////////////////wA==', b'V4M4igxUqaC3VaSsMMApAA=='), (b'////////////////////4A==', b'G21WTHzgudSka0Ytgby1oA=='), (b'////////////////////8A==', b'grGLwJ2ImTyCFoMu40WMkA=='), (b'////////////////////+A==', b'sQgw2V9Y2OzO7QkoJrf+yA=='), (b'/////////////////////A==', b'1ntG6tr4W0xXGh0lrVMaZA=='), (b'/////////////////////g==', b'GJ2qjdG5XA1k9DU+uprTMg=='), (b'/////////////////////w==', b'hVByQ8c7Uo8DKGUIlQlBmw==')]
    extra_pair = (b'AAAAAAAAAAAAAAAAAAAAAA==', b'8mdM2WS60RnYAas952nVwA==')
    challenge = b"HZRhgQ5zIQjHFmeNJl00jA=="

    # Decode the given parameters
    pairs = list(map(lambda pair: (base64.b64decode(pair[0]), base64.b64decode(pair[1])), pairs))
    extra_pair = tuple(map(lambda x: base64.b64decode(x), extra_pair))
    challenge = base64.b64decode(challenge)

    print("Decrypting {}...".format(challenge))

    solution = affine_cipher_attack(pairs, extra_pair, challenge)
    print("Solution: {}".format(solution))


if __name__ == '__main__':
    main()