#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Pasero Christian
# Created Date: SS 2022
# version = '1.0'
# ---------------------------------------------------------------------------
"""  Bachelor project - SS 2022 
SAT-Solver attack for Photon-Beetle-Hash-256 (PhotonBeetle) [https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/photon-beetle-spec-final.pdf]. 
The attack uses the z3-SAT Solver and operates on 64bit preimage length and an
adjustable hashing output length of arbitrary size <= 128
"""
# ---------------------------------------------------------------------------
################################# IMPORTS ###########################################
import time
from z3 import *

################################# CONSTANTS ###########################################
ROUND_NUM  = 1
HASH_LEN    = 32
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



################################# TEST HASHES #########################################
# Testhashes 128bit
allHashes128 = [
    BitVecVal(0x192415816174853a192415816174853a, 128),
    BitVecVal(0xf99f45524281c15ff99f45524281c15f, 128),
    BitVecVal(0xa5d90e13d86fc740a5d90e13d86fc740, 128),
    BitVecVal(0x28e4a717f4bd562628e4a717f4bd5626, 128),
    BitVecVal(0xc481db8ba4484ebc481db8ba4484eb56, 128),
    BitVecVal(0x307824dba14dd818307824dba14dd818, 128),
    BitVecVal(0xc2dbc7c4d564be3cc2dbc7c4d564be3c, 128),
    BitVecVal(0x6e8450c381f2f0c56e8450c381f2f0c5, 128),
    BitVecVal(0x224ee586ca4c2f11224ee586ca4c2f11, 128),
    BitVecVal(0x34a86e19af7619a434a86e19af7619a4, 128)]



############################## SAT SOLVER CHECKER ####################################
def checkSat(s: Solver, hash: BitVec, p_img: BitVec, start_time: time):
    '''checks if it is satisfiable and prints the values'''
    if s.check() == sat:
        end_time = time.time()
        m = s.model()
        print(f"Rounds  : {ROUND_NUM}")
        print(f"HashLen : {HASH_LEN}")
        print(f"Hash    : {hex(int(str(m[hash])))[:2+(int(HASH_LEN))]}")
        print(f"F_Hash  : {hex(int(str(m[hash])))}")
        print(f"F_PImg  : {hex(int(str(m[p_img])))}")
        print(f"exe_time: {math.ceil(end_time - start_time)}s")
    else:
        print("ERROR")



################################ FIELD MULT ########################################
def fieldMult(s: Solver, r_: int, k_: int, i_: int, j_: int, x_: int, b_: int) -> list:
    '''Helpfer function for MixColumns'''
    ret = [BitVec(f"ret_fieldMult_r({r_})_k{k_}_i{i_}_j{j_}{l}", 4) for l in range(5)]
    s.add(ret[0] == 0x0)
    x = [BitVec(f"x_fieldMult_r({r_})_k{k_}_i{i_}_j{j_}{l}", 4) for l in range(5)]
    s.add(x[0] == x_)
    # if construction
    for i in range(4):
        s.add(ret[i+1] == If(Extract(i,i,b_) == BitVecVal(0x1, 1), ret[i] ^ x[i], ret[i]))
        #x = (x << 1)^0x3
        iftrue = BitVec(f"ift_fieldMult_r({r_})_k{k_}_i{i_}_j{j_}{i}", 4)
        s.add(Extract(0,0,iftrue) == 0x1)
        s.add(Extract(1,1,iftrue) == (Extract(0,0,x[i]) ^ BitVecVal(0x1, 1)))
        s.add(Extract(3,2,iftrue) == (Extract(2,1,x[i])))
        #x = (x << 1)
        iffalse = BitVec(f"iff_fieldMult_r({r_})_k{k_}_i{i_}_j{j_}{i}", 4)
        s.add(Extract(0,0,iffalse) == 0x0)
        s.add(Extract(3,1,iffalse) == Extract(2,0,x[i]))
        s.add(x[i+1] == If(Extract(3,3, x[i]) == BitVecVal(0x1, 1), iftrue, iffalse))
    return ret[-1]



################################ MIX COLUMNS ########################################
def mixColumns(s: Solver, r: int, IS_: list) -> list:
    '''MixColumns function of the permutation'''
    IS = [[BitVec(f"IS_mixColumns_r({r})_[{i}][{j}]", 4) for j in range(8)] for i in range(8)]
    for j in range(8):
        IS_temp = [[BitVec(f"IS_mix_column_temp_r({r})[{j}]{i}_it{it}", 4) for i in range(8)] for it in range(8)]
        for i in range(8):
            curr_sum = [BitVec(f"MC_currSum_r({r})_[{i}][{j}]_{k}", 4) for k in range(9)]
            s.add(curr_sum[0] == 0x0)
            for k in range(8):
                s.add(curr_sum[k+1] == curr_sum[k] ^ fieldMult(s, r, k, i, j,  MixColMatrix[i][k], IS_[k][j]))
            for l in range(8):
                s.add(IS_temp[i][l] == curr_sum[l+1])
        for i in range(8):    
            s.add(IS[i][j] == IS_temp[i][7])
    return IS



################################ SHIFT ROWS ########################################
def shiftRows(s: Solver, r: int, IS_: list) -> list:
    '''ShiftRows function of the permutation'''
    IS = [[BitVec(f"IS_shiftRows_r({r})_[{i}][{j}]", 4) for j in range(8)] for i in range(8)]
    for i in range(8):
        for j in range(8):
            s.add(IS[i][j] == IS_[i][(i+j)%8])
    return IS



################################### S-BOX ##########################################
def sBox(s: Solver, r: int, i: int, j: int, inp: BitVec) -> BitVec:
    '''Selfmade S-Box'''
    out = BitVec(f"sbox_r({r})[{i}][{j}]", 4)
    x = [BitVec(f"sbox_bool_r({r})[{i}][{j}]_{k}", 1) for k in range(4)]
    for k in range(4):
        s.add(x[k] == Extract(k, k, inp))
    y_4 = (~x[3]&((x[1]&x[0])|(~x[1]&~x[0])|(x[2]&x[1]&~x[0])))|(x[3]&~x[2]&(x[0]|x[1]))
    y_3 = (~x[3]&((~x[2]&~(x[1]&x[0]))|(x[2]&x[1]&x[0])))|(x[3]&((~x[2]&(x[1]^x[0]))|(x[2]&~x[1])))
    y_2 = (~x[3]&((~x[2]&x[1])|(x[2]&x[1]&~x[0])))|(x[3]&((~x[1]&x[0])|(~x[2]&~x[0])|(x[2]&x[1]&x[0])))
    y_1 = (~x[3]&((~x[2]&x[0])|(x[2]&((x[0]&x[1])|(~x[0]&~x[1])))))|(x[1]&~x[1])|(x[3]&((~x[2]&~x[0])|x[2]&(x[0]^x[1])))
    for i, cond in enumerate([y_1, y_2, y_3, y_4]):
        s.add(Extract(i, i, out) == cond)
    return out



################################# SUB CELLS ########################################
def subCells(s: Solver, r: int, IS_: list) -> list:
    '''SubCells function of the permutation'''
    IS = [[BitVec(f"IS_subCells_r({r})_[{i}][{j}]", 4) for j in range(8)] for i in range(8)]
    for i in range(8):
        for j in range(8):
            s.add(IS[i][j] == sBox(s, r, i, j, IS_[i][j]))
    return IS



################################### ADD KEY ##########################################
def addKey(s: Solver, r:int, IS_: list) -> list:
    '''AddKey function of the permutation'''
    IS = [[BitVec(f"IS_addKey_r({r})_[{i}][{j}]", 4) for j in range(8)] for i in range(8)]
    for i in range(8):
        s.add(IS[i][0] == IS_[i][0] ^ constants[i][r])
    for i in range(8):
        for j in range(1,8,1):
            s.add(IS[i][j] == IS_[i][j])
    return IS



################################## PERMUTATION #######################################
def permutation(s: Solver, IS: list) -> list:
    '''Permutation of photon-256'''
    for r in range(ROUND_NUM):
        IS = addKey(s, r, IS)
        IS = subCells(s, r, IS)
        IS = shiftRows(s, r, IS)
        IS = mixColumns(s, r, IS)
    return IS



################################### INIT ##########################################
def init(s: Solver, M_1: int) -> list:
    '''Initializes the InternalState IS'''
    IS = [[BitVec(f"IS_init[{i}][{j}]", 4) for j in range(8)] for i in range(8)]
    for i in range(8):
        for j in range(8):
            if i < 2:
                s.add(IS[i][j] == Extract(4*(i*8+j) + 3,4*(i*8+j),M_1))
            elif i == 2 and j == 0:
                s.add(IS[i][j] == 0x1)
            elif i == 7 and j == 7:
                s.add(IS[i][j] == 0x2)
            else:
                s.add(IS[i][j] == 0x0)
    return IS



################################ NORMAL EXECUTION ####################################
def forward_calc():
    '''This is the normal hash function execution, where the message is given and
    the hash is calculated'''
    s = Solver()
    start = time.time()
    # 64bit message
    M_1 = BitVec("M_1_inp", 64)
    s.add(M_1 == 0xaaaaaaaaaaaaaaaa)
    # initialize x and y vectors
    IS_init = init(s, M_1)
    IS = permutation(s, IS_init)
    hash = BitVec("Hash_out", 256)
    for i in range(8):
        for j in range(0,7,2):
            s.add(Extract(255-4*(i*8+j), 255-4*(i*8+j)-3, hash ) == IS[i][j+1])
            s.add(Extract(255-4*(i*8+j)-4, 255-4*(i*8+j)-7, hash ) == IS[i][j])
    checkSat(s, hash, M_1, start)



####################################   ATTACK   ####################################
def backward_attack():
    '''This is the SAT-Solver attack'''
    s = Solver()
    start = time.time()
    # 64bit message
    M_1 = BitVec("M_1_inp", 64)
    # crypto hash function
    IS_init = init(s, M_1)
    IS = permutation(s, IS_init)
    hash = BitVec("Hash_out", 256)
    for i in range(8):
        for j in range(0,7,2):
            s.add(Extract(255-4*(i*8+j), 255-4*(i*8+j)-3, hash ) == IS[i][j+1])
            s.add(Extract(255-4*(i*8+j)-4, 255-4*(i*8+j)-7, hash ) == IS[i][j])
    s.add(Extract(255, 255-HASH_LEN*4, hash) == Extract(127, 127-HASH_LEN*4, HASH_VALUE))
    checkSat(s, hash, M_1, start)



#################################### Attributes ####################################
def setAttr():
    '''sets the attributes which were given a paramater'''
    if len(sys.argv) != 4:
        print("Usage: python3 attack.py ROUNDNUM HASHLEN[bit] HashIndex[0-9]")
        exit()
    global ROUND_NUM
    global HASH_LEN
    global HASH_VALUE
    ROUND_NUM   = int(sys.argv[1])
    HASH_LEN    = int(int(sys.argv[2])/4)
    HashIndex   = int(sys.argv[3])
    HASH_VALUE  = allHashes128[HashIndex]



####################################   MAIN   ####################################
def main():
    setAttr()
    #forward_calc()    # normal hash usage
    backward_attack()  # SAT-Solver attack

if __name__ == '__main__':
    main()