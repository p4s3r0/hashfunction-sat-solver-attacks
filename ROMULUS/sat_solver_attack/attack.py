#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Pasero Christian
# Created Date: SS 2022
# version = '1.0'
# ---------------------------------------------------------------------------
"""  Bachelor thesis - SS 2022 
SAT-Solver attack for ROMULUS-H (ASCON) [https://romulusae.github.io/romulus/]. 
The attack uses the z3-SAT Solver and operates on 64bit preimage length and an
adjustable hashing output length of arbitrary size <= 128
"""
# ---------------------------------------------------------------------------
################################# IMPORTS ###########################################
from z3 import *
import time
import math

################################# CONSTANTS ###########################################
ROUND_NUM = None
HashLen   = None
HashValue = None
HashIndex = None


################################# TEST HASHES #########################################
# Testhashes 64bit
allHashes64 = [
    0xbea4781fbea4781f, 
    0x0101010101010101, 
    0x189a3b92189a3b92, 
    0x71fabd3871fabd38, 
    0x4fabe2814fabe281, 
    0xf219462ef219462e, 
    0xfeba1267feba1267,
    0x123f71bc123f71bc, 
    0xb2b91842b2b91842, 
    0xbb27194abb27194a]


################################ SBOX ####################################
def sbox(s, r, byte_inp, i_p, j_p):
    result = BitVec("SBOX_r(" + str(r) + ")_IS[" + str(i_p) + "][" + str(j_p) + "]", 8)
    inp = [Extract(i, i, byte_inp) for i in range(8)]

    # first line
    nor_0_0 = ~(inp[7] | inp[6])
    xor_0_1 = nor_0_0 ^ inp[4]
    nor_0_2 = ~(inp[3] | inp[2])
    xor_0_3 = nor_0_2 ^ inp[0]

    # second line
    nor_1_0 = ~(inp[2] | inp[1])
    xor_1_1 = nor_1_0 ^ inp[6]
    nor_1_2 = ~(xor_0_1 | xor_0_3)
    xor_1_3 = inp[5] ^ nor_1_2

    # third line
    nor_2_0 = ~(xor_0_3 | inp[3])
    xor_2_1 = inp[1] ^ nor_2_0
    nor_2_2 = ~(xor_1_1 | xor_1_3)
    xor_2_3 = inp[7] ^ nor_2_2

    # fourth line
    nor_3_0 = ~(xor_1_3 | xor_0_1)
    xor_3_1 = inp[3] ^ nor_3_0
    nor_3_2 = ~(xor_2_1 | xor_2_3)
    xor_3_3 = inp[2] ^ nor_3_2

    s.add(Extract(0, 0, result) == xor_3_3)
    s.add(Extract(1, 1, result) == xor_2_3)
    s.add(Extract(2, 2, result) == xor_1_1)
    s.add(Extract(3, 3, result) == xor_2_1)
    s.add(Extract(4, 4, result) == xor_3_1)
    s.add(Extract(5, 5, result) == xor_0_3)
    s.add(Extract(6, 6, result) == xor_0_1)
    s.add(Extract(7, 7, result) == xor_1_3)
    return result



################################# ADD CONSTANTS LAYER #########################################
def addConstants(s, r, IS_p, rc_p):
    rc = BitVec("ADDC_r(" + str(r) + ")_rc", 8)
    s.add(Extract(5, 1, rc) == Extract(4, 0, rc_p))
    s.add(Extract(0, 0, rc) == Extract(5, 5, rc_p) ^ Extract(4, 4, rc_p) ^ BitVecVal(0x1, 1))
    s.add(Extract(7, 6, rc) == 0x0)

    c_0 = BitVec("ADDC_r(" + str(r) + ")_c0", 8)
    s.add(Extract(3, 0, c_0) == Extract(3, 0, rc))
    s.add(Extract(7, 4, c_0) == 0x0)

    c_1 = BitVec("ADDC_r(" + str(r) + ")_c1", 8)
    s.add(Extract(1, 0, c_1) == Extract(5, 4, rc))
    s.add(Extract(7, 2, c_1) == 0x0)

    c_2 = BitVecVal(0x2, 8)

    IS = [[ BitVec("ADDC_r(" + str(r) + ")_IS[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]
    for i in range(4):
        for j in range(4):
            if j == 0:
                if i == 0:
                    s.add(IS[i][j] == IS_p[i][j] ^ c_0)
                    continue
                elif i == 1:
                    s.add(IS[i][j] == IS_p[i][j] ^ c_1)
                    continue
                elif i == 2:
                    s.add(IS[i][j] == IS_p[i][j] ^ c_2)
                    continue
            s.add(IS[i][j] == IS_p[i][j])
    return IS, rc



################################# CELL SWITCHING #########################################
def cellSwitching(s, r, TK_p, TK_index):
    TK = [[ BitVec("ADDK_r(" + str(r) + ")_CESW_TK" + str(TK_index) + "[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]
    s.add(TK[0][0] == TK_p[2][1])
    s.add(TK[0][1] == TK_p[3][3])
    s.add(TK[0][2] == TK_p[2][0])
    s.add(TK[0][3] == TK_p[3][1])
    s.add(TK[1][0] == TK_p[2][2])
    s.add(TK[1][1] == TK_p[3][2])
    s.add(TK[1][2] == TK_p[3][0])
    s.add(TK[1][3] == TK_p[2][3])
    s.add(TK[2][0] == TK_p[0][0])
    s.add(TK[2][1] == TK_p[0][1])
    s.add(TK[2][2] == TK_p[0][2])
    s.add(TK[2][3] == TK_p[0][3])
    s.add(TK[3][0] == TK_p[1][0])
    s.add(TK[3][1] == TK_p[1][1])
    s.add(TK[3][2] == TK_p[1][2])
    s.add(TK[3][3] == TK_p[1][3])
    return TK



################################# LFSR #########################################
def LFSR(s, r, TK_p, TK_index):
    new_tweakey = [[ BitVec("ADDK_r(" + str(r) + ")_LFSR_TK" + str(TK_index) + "[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]

    for i in range(2, 4, 1):
        for j in range(4):
            s.add(new_tweakey[i][j] == TK_p[i][j])

    if TK_index == 2:
        for i in range(2):
            for j in range(4):
                s.add(Extract(7, 7, new_tweakey[i][j]) == Extract(6, 6, TK_p[i][j]))
                s.add(Extract(6, 6, new_tweakey[i][j]) == Extract(5, 5, TK_p[i][j]))
                s.add(Extract(5, 5, new_tweakey[i][j]) == Extract(4, 4, TK_p[i][j]))
                s.add(Extract(4, 4, new_tweakey[i][j]) == Extract(3, 3, TK_p[i][j]))
                s.add(Extract(3, 3, new_tweakey[i][j]) == Extract(2, 2, TK_p[i][j]))
                s.add(Extract(2, 2, new_tweakey[i][j]) == Extract(1, 1, TK_p[i][j]))
                s.add(Extract(1, 1, new_tweakey[i][j]) == Extract(0, 0, TK_p[i][j]))
                s.add(Extract(0, 0, new_tweakey[i][j]) == Extract(7, 7, TK_p[i][j]) ^ Extract(5, 5, TK_p[i][j]))
    else:
        for i in range(2):
            for j in range(4):
                s.add(Extract(7, 7, new_tweakey[i][j]) == Extract(0, 0, TK_p[i][j]) ^ Extract(6, 6, TK_p[i][j]))
                s.add(Extract(6, 6, new_tweakey[i][j]) == Extract(7, 7, TK_p[i][j]))
                s.add(Extract(5, 5, new_tweakey[i][j]) == Extract(6, 6, TK_p[i][j]))
                s.add(Extract(4, 4, new_tweakey[i][j]) == Extract(5, 5, TK_p[i][j]))
                s.add(Extract(3, 3, new_tweakey[i][j]) == Extract(4, 4, TK_p[i][j]))
                s.add(Extract(2, 2, new_tweakey[i][j]) == Extract(3, 3, TK_p[i][j]))
                s.add(Extract(1, 1, new_tweakey[i][j]) == Extract(2, 2, TK_p[i][j]))
                s.add(Extract(0, 0, new_tweakey[i][j]) == Extract(1, 1, TK_p[i][j]))
    return new_tweakey



################################# ADD KEY LAYER #########################################
def addKey(s, r, IS_p, TK1_p, TK2_p, TK3_p):
    # XOR Tweakeys with internal state
    IS = [[ BitVec("ADDK_r(" + str(r) + ")_IS[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]
    for i in range(4):
        for j in range(4):
            if i < 2:
                s.add(IS[i][j] == IS_p[i][j] ^ TK1_p[i][j] ^ TK2_p[i][j] ^ TK3_p[i][j])
            else:
                s.add(IS[i][j] == IS_p[i][j])

    TK1_cellSwitching = cellSwitching(s, r, TK1_p, 1)
    TK2_cellSwitching = cellSwitching(s, r, TK2_p, 2)
    TK3_cellSwitching = cellSwitching(s, r, TK3_p, 3)

    # LFSR
    TK2_lfsr = LFSR(s, r, TK2_cellSwitching, 2)
    TK3_lfsr = LFSR(s, r, TK3_cellSwitching, 3)
    return IS, TK1_cellSwitching, TK2_lfsr, TK3_lfsr



################################# SHIFT ROWS LAYER #########################################
def shiftRows(s, r, IS_p):
    IS = [[ BitVec("SHRO_r(" + str(r) + ")_IS[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]
    for i in range(4):
        s.add(IS[0][i] == IS_p[0][i])
    s.add(IS[1][0] == IS_p[1][3])
    s.add(IS[1][1] == IS_p[1][0])
    s.add(IS[1][2] == IS_p[1][1])
    s.add(IS[1][3] == IS_p[1][2])
    s.add(IS[2][0] == IS_p[2][2])
    s.add(IS[2][1] == IS_p[2][3])
    s.add(IS[2][2] == IS_p[2][0])
    s.add(IS[2][3] == IS_p[2][1])
    s.add(IS[3][0] == IS_p[3][1])
    s.add(IS[3][1] == IS_p[3][2])
    s.add(IS[3][2] == IS_p[3][3])
    s.add(IS[3][3] == IS_p[3][0])
    return IS



################################# MIX COLUMNS LAYER #########################################
def mixColumns(s, r, IS_p):
    IS = [[ BitVec("MIXC_r(" + str(r) + ")_IS[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]
    for i in range(4):
        IS_xored = [BitVec("MIXC_r(" + str(r) + ")_xored_[" + str(j) + "][" + str(i) + "]", 8) for j in range(3)]
        s.add(IS_xored[0] == IS_p[1][i] ^ IS_p[2][i])
        s.add(IS_xored[1] == IS_p[2][i] ^ IS_p[0][i])
        s.add(IS_xored[2] == IS_p[3][i] ^ IS_xored[1])

        s.add(IS[3][i] == IS_xored[1])
        s.add(IS[2][i] == IS_xored[0])
        s.add(IS[1][i] == IS_p[0][i])
        s.add(IS[0][i] == IS_xored[2])
    return IS



################################# ROUND FUNCTION #########################################
def roundFunction(s, IS_p, TK1_p, TK2_p, TK3_p, round_const_p, r):
    # SubCells
    IS_sbox = [[ sbox(s, r, IS_p[i][j], i, j) for j in range(4)] for i in range(4)]
    # AddConstants
    IS_addConst, rc_addConst = addConstants(s, r, IS_sbox, round_const_p)
    # AddRoundTweakey
    IS_addKey, TK1_addKey, TK2_addKey, TK3_addKey = addKey(s, r, IS_addConst, TK1_p, TK2_p, TK3_p)
    # ShiftRows
    IS_shiftRows = shiftRows(s, r, IS_addKey)
    # MixColumn
    IS_mixColumn = mixColumns(s, r, IS_shiftRows)
    return IS_mixColumn, TK1_addKey, TK2_addKey, TK3_addKey, rc_addConst



################################# SKINNY ALGORITHM #########################################
def skinny(s, M):
    # Create Tweakeys
    TK1_init = [[BitVec("INIT_TK1[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]
    for i in range(4):
        for j in range(4):
            s.add(TK1_init[i][j] == 0x0)

    TK2_init = [[BitVec("INIT_TK2[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]
    pos_in_vector = 255
    for i in range(4):
        for j in range(4):
            s.add(TK2_init[i][j] == Extract(pos_in_vector, pos_in_vector - 7, M))
            pos_in_vector = pos_in_vector - 8

    TK3_init = [[BitVec("INIT_TK3[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]
    pos_in_vector = 127
    for i in range(4):
        for j in range(4):
            s.add(TK3_init[i][j] == Extract(pos_in_vector, pos_in_vector - 7, M))
            pos_in_vector = pos_in_vector - 8

    L = BitVec("L_init", 128)
    s.add(L == 0x2)

    # Create Internal cipher state
    IS = [[BitVec("INIT_IS[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]
    pos_in_vector = 0
    for i in range(4):
        for j in range(4):
            s.add(IS[i][j] == Extract(pos_in_vector + 7, pos_in_vector, L))
            pos_in_vector = pos_in_vector + 8

    # Round function
    round_const = BitVec("round_const_r(0)", 8)
    s.add(round_const == 0x0)
    for r in range(ROUND_NUM):
        IS, TK1_init, TK2_init, TK3_init, round_const = roundFunction(s, IS, TK1_init, TK2_init, TK3_init, round_const, r)

    HASH = [[BitVec("HASH[" + str(i) + "][" + str(j) + "]", 8) for j in range(4)] for i in range(4)]
    for i in range(4):
        for j in range(4):
            if i == 0 and j == 0:
                s.add(HASH[0][0] == IS[0][0] ^ 0x2)
                continue
            s.add(HASH[i][j] == IS[i][j])
    return HASH



################################# PADDING #########################################
def padMessage(s, m):
    Mp = BitVec("padded_message", 256)
    s.add(Extract(255, 255 - 127, Mp) == m)
    s.add(Extract(5,0, Mp) == 0x10) #length = 16
    return Mp



#################################### Attributes ####################################
def setAttr():
    if len(sys.argv) != 4:
        print("Usage: python3 attack.py ROUNDNUM HASHLEN[bit] HashIndex[0-9]")
        exit()
    global ROUND_NUM
    global PA_ROUNDS
    global PB_ROUNDS
    global HashLen
    global HashIndex
    global HashValue

    ROUND_NUM = int(sys.argv[1])
    HashLen = int(sys.argv[2])
    HashIndex = int(sys.argv[3])

    HashValue = allHashes64[HashIndex]
    PA_ROUNDS = (0, ROUND_NUM)
    PB_ROUNDS = (0, ROUND_NUM)



#################################### MAIN ####################################
def main():
    setAttr()
    start = time.time()
    s = Solver()
    M_1 = BitVec("M_1_inp", 128)
    # padding message
    M = padMessage(s, M_1)

    # enter hiroses DB
    HASH = skinny(s, M)

    for i in range(HashLen//32):
        for j in range(4):
            s.add(HASH[i][j] == HashValue >> (HashLen - (8 * (i * 4 + j +1))) & 0xff)
    if s.check() == sat:
        end = time.time()
        m = s.model()
        print("HashLen  : " + str(HashLen))
        print("Rounds   : " + str(PA_ROUNDS[1]))
        print("HashV    : " + hex(int(str(HashValue))))
        print("FoundHash: 0x", end="")
        for i in range(4):
            for j in range(4):
                print(hex(int(str(m[HASH[i][j]])))[2:], end="")
        print("\nFoundPImg: " +  hex(int(str(m[M]))))
        print("Execution time: " + str(math.ceil(end - start)) + "s")
    else:
        print("ERROR")



if __name__ == '__main__':
    main()
    

