#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Pasero Christian
# Created Date: SS 2022
# version = '1.0'
# ---------------------------------------------------------------------------
"""  Bachelor thesis - SS 2022 
SAT-Solver attack for ASCON-XOF (ASCON) [https://ascon.iaik.tugraz.at/]. 
The attack uses the z3-SAT Solver and operates on 64bit preimage length and an
adjustable hashing output length of arbitrary size <= 128
"""
# ---------------------------------------------------------------------------
################################# IMPORTS ###########################################
from z3 import *
import time
import math
import sys

################################# CONSTANTS ###########################################
ROUND_NUM = 8
HashLen   = 20
HashValue = 0xffffffff
PA_ROUNDS = (0, ROUND_NUM)
PB_ROUNDS = (0, ROUND_NUM)


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


####################### ROUND CONSTANT ADDITION LAYER ###########################
def roundConstantAddition(s, inp, out, round_nr):
    for i in [0, 1, 3, 4]:
        s.add(out[i] == inp[i])

    constants = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
    constant = constants[round_nr]

    constVal = BitVecVal(constant, 64)
    s.add(out[2] == inp[2] ^ constVal)



################################ SBOX ######################################
def sbox(s, inp, out):
    # beginning XORs
    xb_0 = inp[0] ^ inp[4]
    xb_2 = inp[1] ^ inp[2]
    xb_4 = inp[3] ^ inp[4]
    # middle XORs
    xm_0 = xb_0   ^ ( xb_2   & ~inp[1])
    xm_1 = inp[1] ^ (~xb_2   &  inp[3])
    xm_2 = xb_2   ^ (~inp[3] &  xb_4)
    xm_3 = inp[3] ^ (~xb_4   &  xb_0)
    xm_4 = xb_4   ^ (~xb_0   &  inp[1])
    # ending XORs
    xe_0 = xm_0 ^ xm_4
    xe_1 = xm_0 ^ xm_1
    xe_2 = ~xm_2
    xe_3 = xm_2 ^ xm_3
    xe_4 = xm_4
    # rules for output of sbox
    s.add(out[0] == xe_0)
    s.add(out[1] == xe_1)
    s.add(out[2] == xe_2)
    s.add(out[3] == xe_3)
    s.add(out[4] == xe_4)



################################ DIFFUSION LAYER ######################################
def diffusionFunction(s, inp, out):
    s.add(out[0] == (inp[0] ^ RotateRight(inp[0], 19) ^ RotateRight(inp[0], 28)))
    s.add(out[1] == (inp[1] ^ RotateRight(inp[1], 61) ^ RotateRight(inp[1], 39)))
    s.add(out[2] == (inp[2] ^ RotateRight(inp[2],  1) ^ RotateRight(inp[2],  6)))
    s.add(out[3] == (inp[3] ^ RotateRight(inp[3], 10) ^ RotateRight(inp[3], 17)))
    s.add(out[4] == (inp[4] ^ RotateRight(inp[4],  7) ^ RotateRight(inp[4], 41)))



############################## PERMUTATION FUNCTION ################################
def pb(s, inp, out, identifier):
    prev_output = []
    prev_output.append([BitVec("pb" + str(identifier) + "cOUT-" + str(i), 64) for i in range(5)]) #rca
    for i in range(0,5):
        s.add(prev_output[0][i] == inp[i])

    for round_nr in range(PB_ROUNDS[0], PB_ROUNDS[1]): #pb round
        rca_out = [BitVec("pb" + str(identifier) + "_rca_"+ "r" + str(round_nr) + "-" + str(i) , 64) for i in range(5)]
        sbx_out = [BitVec("pb" + str(identifier) + "_sbx_"+ "r" + str(round_nr) + "-" + str(i), 64) for i in range(5)]
        ldf_out = [BitVec("pb" + str(identifier) + "_ldf_"+ "r" + str(round_nr) + "-" + str(i), 64) for i in range(5)]

        roundConstantAddition(s, prev_output[round_nr], rca_out, round_nr)
        sbox(s, rca_out, sbx_out)
        diffusionFunction(s, sbx_out, ldf_out)
        prev_output.append(ldf_out)

    s.add(out[0] == prev_output[-1][0])
    s.add(out[1] == prev_output[-1][1])
    s.add(out[2] == prev_output[-1][2])
    s.add(out[3] == prev_output[-1][3])
    s.add(out[4] == prev_output[-1][4])



############################## PERMUTATION FUNCTION ################################
def pa(s, inp, out, identifier):
    prev_output = []
    prev_output.append([BitVec("pa" + str(identifier) + "_init-" + str(i), 64) for i in range(5)]) #rca
    for i in range(0,5):
        s.add(prev_output[0][i] == inp[i])

    for round_nr in range(PA_ROUNDS[0], PA_ROUNDS[1]):
        rca_out = [BitVec("pa" + str(identifier) + "_rca_"+ "r" + str(round_nr) + "-" + str(i) , 64) for i in range(5)]
        sbx_out = [BitVec("pa" + str(identifier) + "_sbx_"+ "r" + str(round_nr) + "-" + str(i), 64) for i in range(5)]
        ldf_out = [BitVec("pa" + str(identifier) + "_ldf_"+ "r" + str(round_nr) + "-" + str(i), 64) for i in range(5)]

        roundConstantAddition(s, prev_output[round_nr], rca_out, round_nr)
        sbox(s, rca_out, sbx_out)
        diffusionFunction(s, sbx_out, ldf_out)
        prev_output.append(ldf_out)

    s.add(out[0] == prev_output[-1][0])
    s.add(out[1] == prev_output[-1][1])
    s.add(out[2] == prev_output[-1][2])
    s.add(out[3] == prev_output[-1][3])
    s.add(out[4] == prev_output[-1][4])



############################# INITIALIZATION OF IV #############################
def init(s, M_1, out):
    #XOF
    init_0 = BitVecVal(0xb57e273b814cd416, 64)
    init_1 = BitVecVal(0x2b51042562ae2420, 64)
    init_2 = BitVecVal(0x66a3a7768ddf2218, 64)
    init_3 = BitVecVal(0x5aad0a7a8153650c, 64)
    init_4 = BitVecVal(0x4f3e0e32539493b6, 64)
    s.add(out[0] == (init_0 ^ M_1))
    s.add(out[1] == init_1)
    s.add(out[2] == init_2)
    s.add(out[3] == init_3)
    s.add(out[4] == init_4)



#################################### Attributes ####################################
def setAttr():
    if len(sys.argv) != 4:
        print("Usage: python3 attack.py ROUNDNUM HASHLEN[bit] HashIndex[0-9]")
        exit()
    global ROUND_NUM
    global HashLen
    global HashValue
    global PA_ROUNDS
    global PB_ROUNDS

    ROUND_NUM = int(sys.argv[1])
    HashLen = int(sys.argv[2])
    HashIndex = int(sys.argv[3])
    HashValue = [allHashes64[HashIndex]]
    PA_ROUNDS = (0, ROUND_NUM)
    PB_ROUNDS = (0, ROUND_NUM)



def backward_attack():
    start = time.time()
    s = Solver()

    M_1 = BitVec("M_1_inp", 64)

    pa0_inp = [BitVec("pa0_inp_-" + str(i), 64) for i in range(5)]
    init(s, M_1, pa0_inp)

    pa0_out = [BitVec("pa0_out-" + str(i), 64) for i in range(5)]
    pa(s, pa0_inp, pa0_out, identifier=0)

    s.add(pa0_out[0] == HashValue[0])
    if HashLen == 128:
        s.add(pa0_out[1] == HashValue[1])

    if s.check() == sat:
        end = time.time()
        m = s.model()
        print("HashLen  : " + str(HashLen))
        print("Rounds   : " + str(PA_ROUNDS[1]))
        print("HASH     : " + str(hex(HashValue[0])), end="")
        if HashLen == 128:
            print(str(hex(HashValue[1]))[2:], end="")
        print("\nFHash_0  : " + hex(int(str(m[pa0_out[0]]))))
        print("FHash_1  : " + hex(int(str(m[pa0_out[1]]))))
        print("FoundPImg: " + hex(int(str(m[M_1]))))
        print("Execution time: " + str(math.ceil(end - start)) + "s")
    else:
        print("ERROR")



####################################   MAIN   ####################################
def main():
    setAttr()
    backward_attack()  # SAT-Solver attack
    

if __name__ == "__main__":
    main()