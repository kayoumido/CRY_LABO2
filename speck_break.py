from Crypto.Util import strxor
from collections import defaultdict

import base64

def xor(a,b):
    return strxor.strxor(a,b)


def list_duplicates(seq):
    """
    source: https://stackoverflow.com/a/5419576
    """
    tally = defaultdict(list)
    for i, item in enumerate(seq):
        tally[item].append(i)

    return ((key, locs) for key, locs in tally.items() if len(locs)>1)

def main():
    BLOCK_SIZE = 4
    with open("Kayoumi_Doran-speck.txt", "r") as f: 
        ct = f.read()

    ct = base64.b64decode(ct)
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    dup_blocks = sorted(list_duplicates(blocks))
    for dup in dup_blocks:
        print(dup)

    i1 = dup_blocks[0][1][0] - 1
    i2 = dup_blocks[0][1][1] - 1

    print(xor(blocks[i1], blocks[i2]))

    i1 = dup_blocks[1][1][0] - 1
    i2 = dup_blocks[1][1][1] - 1

    print(xor(blocks[i1], blocks[i2]))
    # pwd|0000|pwd|0000
    




if __name__ == '__main__':
    main()