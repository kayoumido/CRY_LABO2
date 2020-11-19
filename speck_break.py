from Crypto.Util import strxor
from collections import defaultdict

import base64

def xor(a,b):
    return strxor.strxor(a,b)


def list_duplicates(haystack):
    """
    Find all the duplicates in a given list
    
    source: https://stackoverflow.com/a/5419576

    @type haystack: [bytes]
    @param haystack: list in which to find duplicates

    @rtype: [(bytes, [int])]
    @returns: A list of all the duplicates and the index where they were found
    """
    tally = defaultdict(list)
    for i, item in enumerate(haystack):
        tally[item].append(i)

    return ((key, locs) for key, locs in tally.items() if len(locs) > 1)

def main():
    BLOCK_SIZE = 4
    with open("Kayoumi_Doran-speck.txt", "r") as f: 
        ct = f.read()

    ct = base64.b64decode(ct)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    dup_blocks = sorted(list_duplicates(blocks))

    for dup in dup_blocks:
        i1 = dup[1][0] - 1
        i2 = dup[1][1] - 1
        print(xor(blocks[i1], blocks[i2]))
    

if __name__ == '__main__':
    main()