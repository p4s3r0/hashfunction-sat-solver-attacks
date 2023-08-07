import sys


mlen = 16
ROUND_NUM = 4 #18


KeccakRhoOffsets = [ 0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6 ]
KeccakRoundConstants = [
    0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a,
    0x88, 0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80
]

def printIS(IS):
    for i in range(25):
        print(format(IS[i], '02x'), end="")
    exit()



def index(x, y):
    return (x%5)+5*(y%5)

def ROL8(a, offset):
    ret = 0
    if offset == 0:
        ret =  a
    else:
        ret =  ((a << offset) ^ (a >> (8-offset))) & 0xff
    return ret

def iota(IS, indexRound):
    IS[index(0, 0)] ^= KeccakRoundConstants[indexRound];
    return IS



def chi(IS):
    C = [0 for _ in range(5)]
    for y in range(5):
        for x in range(5):
            C[x] = IS[index(x, y)] ^ ((~IS[index(x+1, y)]) & IS[index(x+2, y)])
        for x in range(5):
            IS[index(x, y)] = C[x]
    return IS



def pi(IS):
    temp = [0 for _ in range(25)]
    for x in range(5):
        for y in range(5):
            temp[index(x, y)] = IS[index(x, y)]
    for x in range(5):
        for y in range(5):
            IS[index(y, 2*x+3*y)] = temp[index(x, y)]
    return IS



def rho(IS):
    for x in range(5):
        for y in range(5):
            IS[index(x, y)] = ROL8(IS[index(x, y)], KeccakRhoOffsets[index(x, y)]);
    return IS



def theta(IS):
    C = [0 for i in range(5)]
    for x in range(5):
        for y in range(5):
            C[x] = C[x] ^ IS[index(x, y)]

    D = [0 for i in range(5)]
    for x in range(5):
        D[x] = ROL8(C[(x+1)%5], 1) ^ C[(x+4)%5]
    
    for x in range(5):
        for y in range(5):
            IS[index(x, y)] = IS[index(x, y)] ^ D[x]
    return IS



def permutation(IS: list):
    for r in range(ROUND_NUM):
        IS = theta(IS)
        IS = rho(IS)
        IS = pi(IS)
        IS = chi(IS)
        IS = iota(IS, r)
    return IS



def init():
    M_1 = [0 for _ in range(25)]
    M_1[0] = 0x4e
    M_1[1] = 0x59
    M_1[2] = 0x02
    M_1[8] = 0x80
    M_1[24] = 0x01 
    return M_1



def setAttr():
    if len(sys.argv) != 4:
        print("Usage: python3 xoodyak.py ROUNDNUM HASHLEN[bit] HashIndex[0-9]")
        exit()
    global ROUND_NUM
    global HashLen
    ROUND_NUM = int(sys.argv[1])
    HashLen = int(sys.argv[2])

def main():
    setAttr()
    M_1 = init()
    IS = permutation(M_1)
    printIS(IS)


if __name__ == '__main__':
    main()
    