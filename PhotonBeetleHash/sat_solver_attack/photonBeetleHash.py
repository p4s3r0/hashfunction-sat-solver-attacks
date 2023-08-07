# Photon Beetle Hash function attack
mlen = 16 # 64bit
ROUNDS = 12

constants = [
    [1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10],
    [0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11],
    [2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9],
    [6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13],
    [14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5],
    [15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4],
    [13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6],
    [9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2]
]
MixColMatrix = [
    [ 2,  4,  2, 11,  2,  8,  5,  6],
	[12,  9,  8, 13,  7,  7,  5,  2],
	[ 4,  4, 13, 13,  9,  4, 13,  9],
	[ 1,  6,  5,  1, 12, 13, 15, 14],
	[15, 12,  9, 13, 14,  5, 14, 13],
	[ 9, 14,  5, 15,  4, 12,  9,  6],
	[12,  2,  2, 10,  3,  1,  1, 14],
	[15,  1, 13, 10,  5, 10,  2,  3]
]

sbox = [12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]
def FieldMult(x: int, b: int) -> list():
    ret = 0
    for i in range(4):
        if (b>>i)&1:
            ret = ret ^ x
        if (x>>3)&1:
            x = (x << 1)^0x3
        else:
            x = x << 1
    return ret & 0xf



def mixColumns(IS: list()) -> list():
    temp = [0 for _ in range(8)]
    for j in range(8):
        for i in range(8):
            sum = 0
            for k in range(8):
                sum = sum ^ FieldMult(MixColMatrix[i][k], IS[k][j])
            temp[i] = sum
        for l in range(8):
            IS[l][j] = temp[l]
    return IS


def shiftRows(IS: list()) -> list():
    temp = [0 for _ in range(8)]
    for i in range(1, 8, 1):
        for j in range(8):
            temp[j] = IS[i][j]
        for j in range(8):
            IS[i][j] = temp[(j + i) % 8]
    return IS


def subCells(IS: list()) -> list():
    for i in range(8):
        for j in range(8):
            IS[i][j] = sbox[IS[i][j]]
    return IS


def addKey(IS: list(), round: int) -> list():
    for i in range(8):
        IS[i][0] = IS[i][0] ^ constants[i][round]
    return IS


def permutation(IS: list) -> list():
    for r in range(ROUNDS):
        IS = addKey(IS, r)
        IS = subCells(IS)
        IS = shiftRows(IS)
        IS = mixColumns(IS)
    return IS



def init(m) -> list():
    '''
    m = 0x123456789
    IS = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]
         [0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
         ....
    '''
    IS = [[((m >> 4*(i*8+j)) & 0xf) for j in range(8)] for i in range(8)]
    IS[2][0] = 0x1
    IS[7][7] = 0x2
    return IS


def printIS(IS: list()) -> None:
    for i in range(8):
        if i == 4:
            print("IS= [", end="")
        else:
            print("    [", end="")
        for j in range(8):
            print(f"{hex(IS[i][j])}", end="")
            if j != 7:
                print(" | ", end="")
        print("]")
    print()

def printHash(IS: list()) -> None:
    print("HASH: 0x", end="")
    for i in range(8):
        for j in range(0, 7, 2):
            print(hex(IS[i][j+1])[2:] + hex(IS[i][j])[2:], end="")


if __name__ == '__main__':
    message = 0xcccccccccccccccc
    IS = init(message)
    IS = permutation(IS)
    #printIS(IS)
    printHash(IS)