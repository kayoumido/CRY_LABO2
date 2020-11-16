from Crypto.Cipher import AES

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
    #TODO
