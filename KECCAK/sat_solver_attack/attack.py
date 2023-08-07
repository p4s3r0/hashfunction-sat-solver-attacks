#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By  : Pasero Christian
# Created Date: SS 2022
# version = '1.0'
# ---------------------------------------------------------------------------
"""  Bachelor project - SS 2022 
SAT-Solver attack for Keccak (Elephant) [https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf]. 
The attack uses the z3-SAT Solver and operates on 64bit preimage length and an
adjustable hashing output length of arbitrary size <= 128
"""
# ---------------------------------------------------------------------------
################################# IMPORTS ###########################################
import time
from z3 import *
class InternalState: pass
class BitVec8Bit: pass
class BitVec200Bit: pass
class BitVec64Bit: pass
################################# CONSTANTS ###########################################
ROUND_NUM  = 1
HASH_LEN   = 32
HASH_VALUE = 0x0

KeccakRhoOffsets = [ 0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6 ]
KeccakRoundConstants = [ 0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a, 0x88, 0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80 ]




################################# TEST HASHES #########################################
# Testhashes 128bit
allHashes128 = [
    BitVecVal(0x54550000400100ffff7f0200ffff3fff, 128),
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
def checkSat(s: Solver, hash: BitVec200Bit, p_img: BitVec64Bit, start_time: time):
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


def buildHash(s: Solver, IS: InternalState) -> BitVec200Bit:
    '''transforms the IS into a 200 bit hash'''
    hash = BitVec("Hash_out", 200)
    for i in range(25):
        s.add(Extract(200-1-8*i, 200-8*(i+1), hash) == IS[i])
    return hash



################################ INDEX ########################################
def index(x: int, y: int):
    return (x%5)+5*(y%5)



################################# ROL8 ########################################
counter_rol8 = 0
def ROL8(s: Solver, a: BitVec8Bit, offset: int) -> BitVec8Bit:
    global counter_rol8
    counter_rol8 += 1
    ret = BitVec(f"ROL8_ret({counter_rol8})", 8)
    if offset == 0:
        s.add(ret == a)
    else:
        s.add(ret == ((a << offset) ^ LShR(a, (8-offset))))
    return ret


################################# THETA ########################################
counter_theta = 0
def theta(s: Solver, IS_: InternalState) -> InternalState:
    global counter_theta
    counter_theta += 1
    C_calc = [[BitVec(f"theta_Ccalc({counter_theta})[{i}]", 8)] for i in range(5)]
    for i in range(5):
        s.add(C_calc[i][-1] == 0x0)
    for x in range(5):
        for y in range(5):
            curr = BitVec(f"theta_curr({counter_theta})[{x}][{y}]", 8)
            s.add(curr == C_calc[x][-1] ^ IS_[index(x, y)])
            C_calc[x].append(curr)
    
    
    C = [C_calc[i][-1] for i in range(5)]

    D = [BitVec(f"theta_D({counter_theta})[{i}]", 8) for i in range(5)]
    for x in range(5):
        s.add(D[x] == ROL8(s, C[(x+1)%5], 1) ^ C[(x+4)%5])


    IS = [BitVec(f"theta_IS({counter_theta})[{i}]", 8) for i in range(25)]
    for x in range(5):
        for y in range(5):
            s.add(IS[index(x, y)] == IS_[index(x, y)] ^ D[x])
    return IS



################################# RHO ########################################
counter_rho = 0
def rho(s: Solver, IS_: InternalState) -> InternalState:
    global counter_rho
    counter_rho += 1
    IS = [BitVec(f"rho_IS({counter_rho})[{i}]", 8) for i in range(25)]
    for x in range(5):
        for y in range(5):
            s.add(IS[index(x, y)] == ROL8(s, IS_[index(x, y)], KeccakRhoOffsets[index(x, y)]))
    return IS



################################# PI ########################################
counter_pi = 0
def pi(s: Solver, IS_: InternalState) -> InternalState:
    global counter_pi
    counter_pi += 1
    IS = [BitVec(f"pi_IS({counter_pi})[{i}]", 8) for i in range(25)]
    for x in range(5):
        for y in range(5):
            s.add(IS[index(y, 2*x+3*y)] == IS_[index(x,y)])
    return IS
    

    
################################# CHI ########################################
counter_chi = 0
def chi(s: Solver, IS_: InternalState) -> InternalState:
    global counter_chi
    counter_chi += 1
    C_calc = [[BitVec(f"chi_Ccalc({counter_chi})[{i}]", 8)] for i in range(5)]
    IS = [BitVec(f"chi_IS({counter_chi})[{i}]", 8) for i in range(25)]
    for y in range(5):
        for x in range(5):
            C_calc[x].append(IS_[index(x, y)] ^ ((~IS_[index(x+1,y)]) & IS_[index(x+2, y)]))
        for x in range(5):
            s.add(IS[index(x, y)] == C_calc[x][-1])
    return IS



################################# IOTA #######################################
counter_iota = 0
def iota(s: Solver, IS_: InternalState, r: int) -> InternalState:
    global counter_iota
    counter_iota += 1
    IS = [BitVec(f"iota_IS({counter_iota})[{i}]", 8) for i in range(25)]
    for x in range(5):
        for y in range(5):
            if x == 0 and y == 0:
                s.add(IS[index(0, 0)] == IS_[index(0, 0)] ^ KeccakRoundConstants[r])
            else:
                s.add(IS[index(x, y)] == IS_[index(x, y)])
    return IS



################################# PERMUTATION ########################################
def permutation(s: Solver, IS_: InternalState) -> InternalState:
    '''The permutation of the Keccak hashfunction'''
    IS = IS_
    for r in range(ROUND_NUM):
        IS = theta(s, IS)
        IS = rho(s, IS)
        IS = pi(s, IS)
        IS = chi(s, IS)
        IS = iota(s, IS, r)
    return IS
    


#################################### INIT ###########################################
def init(s: Solver, M_1: str) -> InternalState:
    '''Initializes the InternalState IS by adding the message and padding'''
    IS = [BitVec(f"IS_init[{i}]", 8) for i in range(25)]
    for i in range(25):
        if    i < 8:   s.add(IS[i] == Extract(i*8+7, i*8, M_1))
        elif  i == 8:  s.add(IS[i] == 0x80)
        elif  i == 24: s.add(IS[i] == 0x01)
        else: s.add(IS[i] == 0x0)
    return IS



################################ NORMAL EXECUTION ####################################
def forward_calc():
    '''This is the normal hash function execution, where the message is given and
    the hash is calculated'''
    s = Solver()
    start = time.time()
    # 64bit message
    M_1 = BitVec("M_1_inp", 64)
    s.add(M_1 == 0xacacacacacacacac)
    # initialize x and y vectors
    IS = init(s, M_1)
    IS = permutation(s, IS)
    hash = buildHash(s, IS)
    checkSat(s, hash, M_1, start)



####################################   ATTACK   ####################################
def backward_attack():
    '''This is the SAT-Solver attack'''
    s = Solver()
    start = time.time()
    # 64bit message
    M_1 = BitVec("M_1_inp", 64)
    # crypto hash function
    IS = init(s, M_1)
    IS = permutation(s, IS)
    hash = buildHash(s, IS)
    s.add(Extract(200-1, 200-1-HASH_LEN*4, hash) == Extract(127, 127-HASH_LEN*4, HASH_VALUE))
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

