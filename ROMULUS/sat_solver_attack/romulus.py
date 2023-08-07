def print4x4(IS, title):
    print(title + ": ")
    for i in range(4):
        line = ""
        for j in range(4):
            line += " "
            #line += "{0:03}".format((IS[i][j]))
            line += "0x{:02X}".format(IS[i][j])
        print(line)

def getx_(number, i):
    return ( number >> i ) & 0x1

def setx_(number, i, new_number):
    mask = 1 << i
    return (number & ~mask) | ((new_number << i) & mask)




r = 0

def sbox(byte_inp):
    a = '0' * (8 - len(bin(byte_inp)[2:])) + str(bin(byte_inp)[2:])
    inp = list()
    for ch in a:
        inp.append(0 if ch == '0' else 1)
    inp = list(reversed(inp))

    # first line
    nor_0_0 = not(inp[7] | inp[6])
    xor_0_1 = nor_0_0 ^ inp[4]
    nor_0_2 = not(inp[3] | inp[2])
    xor_0_3 = nor_0_2 ^ inp[0]

    # second line
    nor_1_0 = not(inp[2] | inp[1])
    xor_1_1 = nor_1_0 ^ inp[6]
    nor_1_2 = not(xor_0_1 | xor_0_3)
    xor_1_3 = inp[5] ^ nor_1_2

    # third line
    nor_2_0 = not(xor_0_3 | inp[3])
    xor_2_1 = inp[1] ^ nor_2_0
    nor_2_2 = not(xor_1_1 | xor_1_3)
    xor_2_3 = inp[7] ^ nor_2_2

    # fourth line
    nor_3_0 = not(xor_1_3 | xor_0_1)
    xor_3_1 = inp[3] ^ nor_3_0
    nor_3_2 = not(xor_2_1 | xor_2_3)
    xor_3_3 = inp[2] ^ nor_3_2

    result = list()
    result.append(xor_1_3)
    result.append(xor_0_1)
    result.append(xor_0_3)
    result.append(xor_3_1)
    result.append(xor_2_1)
    result.append(xor_1_1)
    result.append(xor_2_3)
    result.append(xor_3_3)
    b = 0
    for i in range(len(result)):
        b = int(hex( (b << 1) | result[i] ), 16)
    return hex(b)



def addConstants(PS, rc):
    global r
    rc  = (getx_(rc, 4) << 5) | (getx_(rc, 3) << 4) | (getx_(rc, 2) << 3) | (getx_(rc, 1) << 2) | (getx_(rc, 0) << 1) | (getx_(rc, 5) ^ getx_(rc, 4) ^ True)
    c_0 = (getx_(rc, 3) << 3) | (getx_(rc, 2) << 2) | (getx_(rc, 1) << 1) | (getx_(rc, 0))
    c_1 = (getx_(rc, 5) << 1) | (getx_(rc, 4))
    c_2 = 0x2

    PS[0][0] ^= c_0
    PS[1][0] ^= c_1
    PS[2][0] ^= c_2
    return PS, rc



def mixColumns(PS):
    for i in range(4):
        PS[1][i] ^= PS[2][i]
        PS[2][i] ^= PS[0][i]
        PS[3][i] ^= PS[2][i]

        temp = PS[3][i];
        PS[3][i]=PS[2][i];
        PS[2][i]=PS[1][i];
        PS[1][i]=PS[0][i];
        PS[0][i]=temp;
    return PS



def cellSwitching(B):
    R = [[None for i in range(4)] for j in range(4)]
    R[0][0], R[0][1], R[0][2], R[0][3] = B[2][1], B[3][3], B[2][0], B[3][1]
    R[1][0], R[1][1], R[1][2], R[1][3] = B[2][2], B[3][2], B[3][0], B[2][3]
    R[2][0], R[2][1], R[2][2], R[2][3] = B[0][0], B[0][1], B[0][2], B[0][3]
    R[3][0], R[3][1], R[3][2], R[3][3] = B[1][0], B[1][1], B[1][2], B[1][3]
    return R



def LFSR(TK, TK_i):
    new_tweakey = [[TK[i][j] for j in range(4)] for i in range(4)]
    if TK_i == 2:
        for i in range(2):
            for j in range(4):
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 7, getx_(TK[i][j], 6))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 6, getx_(TK[i][j], 5))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 5, getx_(TK[i][j], 4))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 4, getx_(TK[i][j], 3))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 3, getx_(TK[i][j], 2))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 2, getx_(TK[i][j], 1))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 1, getx_(TK[i][j], 0))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 0, getx_(TK[i][j], 7) ^ getx_(TK[i][j], 5))
    if TK_i == 3:
        for i in range(2):
            for j in range(4):
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 7, (getx_(TK[i][j], 0) ^ getx_(TK[i][j], 6)))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 6, getx_(TK[i][j], 7))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 5, getx_(TK[i][j], 6))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 4, getx_(TK[i][j], 5))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 3, getx_(TK[i][j], 4))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 2, getx_(TK[i][j], 3))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 1, getx_(TK[i][j], 2))
                new_tweakey[i][j] = setx_(new_tweakey[i][j], 0, getx_(TK[i][j], 1))
    return new_tweakey



def addKey(IS, TK_1, TK_2, TK_3):
    # XOR Tweakeys with internal state
    for i in range(2):
        for j in range(4):
            IS[i][j] = IS[i][j] ^ TK_1[i][j] ^ TK_2[i][j] ^ TK_3[i][j]

    # update tweaky permutation
    TK_1 = cellSwitching(TK_1)
    TK_2 = cellSwitching(TK_2)
    TK_3 = cellSwitching(TK_3)

    # LFSR
    TK_2 = LFSR(TK_2, 2)
    TK_3 = LFSR(TK_3, 3)
    return IS, TK_1, TK_2, TK_3



def shiftRows(PS):
    IS = PS
    IS[1][0], IS[1][1], IS[1][2], IS[1][3] = IS[1][3], IS[1][0], IS[1][1], IS[1][2]
    IS[2][0], IS[2][1], IS[2][2], IS[2][3] = IS[2][2], IS[2][3], IS[2][0], IS[2][1]
    IS[3][0], IS[3][1], IS[3][2], IS[3][3] = IS[3][1], IS[3][2], IS[3][3], IS[3][0]
    return IS;



def roundFunction(PS, TK_1, TK_2, TK_3, round_const):
    global r
    # SubCells
    IS = [[ int(sbox(PS[j][i]), 16) for i in range(4)] for j in range(4)]
    # AddConstants
    IS, rc = addConstants(IS, round_const)

    # AddRoundTweakey
    IS, TK_1, TK_2, TK_3 = addKey(IS, TK_1, TK_2, TK_3)
    # ShiftRows
    IS = shiftRows(IS);
    # MixColumn
    IS = mixColumns(IS)

    return IS, TK_1, TK_2, TK_3, rc



def skinny(L, R, M):
    global r
    # Create Tweakeys
    TK_1 = [[ (R >> (128 - 8 * (i * 4 + j + 1))) & 0xFF for j in range(4)] for i in range(4)]
    TK_2 = [[ (M >> (256 - 8 * (i * 4 + j + 1))) & 0xFF for j in range(4)] for i in range(4)]
    TK_3 = [[ (M >> (256 - 128 - 8 * (i * 4 + j + 1))) & 0xFF for j in range(4)] for i in range(4)]
    L ^= 0x2
    hh = [[ 0 for j in range(4)] for i in range(4)]
    hh[0][0] = 0x2

    # Create Internal cipher state
    IS = [[ (L >> (128 - 8 * (i * 4 + j + 1))) & 0xFF for j in range(3, -1, -1)] for i in range(3, -1, -1)]
    # Round function
    round_const = 0x0
    for _ in range(40):
        IS, TK_1, TK_2, TK_3, round_const = roundFunction(IS, TK_1, TK_2, TK_3, round_const)
        r = r + 1

    # XOR hh, so that first bit is correct
    IS[0][0] ^= 0x2
    return IS



def CF_Block(L, R, M):
    return skinny(L, R, M)



def padMessage(M):
    # Message | 0^(256-len(Message-1) | len(Message)
    Mp = 0x0
    for i in range(len(M)):
        Mp = int(hex( (Mp << 8) | ord(M[i]) ), 16)
    Mp = Mp << (256 - 8 * len(M)) | (len(M))
    return Mp



def printHash(H):
    hash = ""
    for i in range(4):
        for j in range(4):
            hash += str(hex(H[i][j]))[2:]
    print("hash: 0x" + hash.upper())


def main():
    inp = "a"

    # padding message
    M = padMessage(inp)

    #initialize L and R
    L = 0x0
    R = 0x0

    # enter hiroses DB
    Hash = CF_Block(L, R, M)

    printHash(Hash)

if __name__ == "__main__":
    main()

