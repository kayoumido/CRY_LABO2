from Crypto.Util import strxor
from collections import defaultdict

import base64

def xor(a,b):
    return strxor.strxor(a,b)


def list_duplicates(l):
    """
    Find all the duplicates in a given list

    @type l: [bytes]
    @param l: list in which to find duplicates

    @rtype: [(bytes, [int])]
    @returns: A list of all the duplicates and the index where they were found
    """
    tracker = defaultdict(list)
    # keep track of every elements and the position at which they were found
    for i, item in enumerate(l):
        tracker[item].append(i)

    # return only the items (and indexes) that were found more than once
    return ((item, indexes) for item, indexes in tracker.items() if len(indexes) > 1)

def main():
    BLOCK_SIZE = 4
    with open("Kayoumi_Doran-speck.txt", "r") as f: 
        ct = f.read()

    ct = base64.b64decode(ct)
    # split the cipher into blocks of <BLOCK_SIZE> size
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    # find all the duplicates
    dup_blocks = sorted(list_duplicates(blocks))

    # find the password
    # Note: Technically, only the first dup can be used to find the password.
    #       But just to be safe, all the dups are used
    for dup in dup_blocks:
        # the password can be found by xoring the blocs found
        # before the dups

        i1 = dup[1][0] - 1
        i2 = dup[1][1] - 1
        print(xor(blocks[i1], blocks[i2]))
    

if __name__ == '__main__':
    main()